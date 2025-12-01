import os
import json
import time
from flask import Flask, render_template, request, send_from_directory, redirect, url_for, abort
from detector import analyze_pcap
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit

UPLOAD_DIR = 'uploads'
RESULT_DIR = 'results'
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RESULT_DIR, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_DIR
app.config['RESULT_FOLDER'] = RESULT_DIR
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

def save_result(result, original_filename):
    """Save analysis result to JSON file"""
    ts = int(time.time())
    safe = f"result_{ts}_{os.path.basename(original_filename)}.json"
    path = os.path.join(app.config['RESULT_FOLDER'], safe)
    with open(path, 'w') as f:
        json.dump(result, f, indent=2, default=str)
    return safe

@app.route('/')
def index():
    """Main upload page"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    """Handle PCAP file upload and analysis"""
    if 'pcap' not in request.files:
        return 'No file part', 400
    
    file = request.files['pcap']
    if file.filename == '':
        return 'No selected file', 400
    
    # Validate file extension
    if not file.filename.lower().endswith(('.pcap', '.pcapng', '.cap')):
        return 'Invalid file type. Please upload a PCAP file.', 400
    
    fname = file.filename
    savepath = os.path.join(app.config['UPLOAD_FOLDER'], fname)
    file.save(savepath)
    
    try:
        # Analyze PCAP
        results = analyze_pcap(savepath)
        
        # Check for errors
        if 'error' in results:
            return f"Analysis error: {results['error']}", 400
        
        # Save results
        resfile = save_result(results, fname)
        
        # Clean up uploaded file (optional)
        # os.remove(savepath)
        
        return redirect(url_for('results', resfile=resfile))
    
    except Exception as e:
        return f"Error analyzing PCAP: {str(e)}", 500

@app.route('/results/<resfile>')
def results(resfile):
    """Display analysis results"""
    path = os.path.join(app.config['RESULT_FOLDER'], resfile)
    if not os.path.exists(path):
        abort(404)
    
    with open(path) as f:
        results = json.load(f)
    
    return render_template('results.html', results=results, resfile=resfile)

@app.route('/history')
def history():
    """Show analysis history"""
    files = sorted(os.listdir(app.config['RESULT_FOLDER']), reverse=True)
    
    # Get file metadata
    file_info = []
    for fname in files:
        if fname.endswith('.json'):
            path = os.path.join(app.config['RESULT_FOLDER'], fname)
            mtime = os.path.getmtime(path)
            file_info.append({
                'name': fname,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))
            })
    
    return render_template('history.html', files=file_info)

@app.route('/download/json/<resfile>')
def download_json(resfile):
    """Download results as JSON"""
    path = os.path.join(app.config['RESULT_FOLDER'], resfile)
    if not os.path.exists(path):
        abort(404)
    return send_from_directory(app.config['RESULT_FOLDER'], resfile, as_attachment=True)

@app.route('/download/pdf/<resfile>')
def download_pdf(resfile):
    """Generate and download PDF report"""
    path = os.path.join(app.config['RESULT_FOLDER'], resfile)
    if not os.path.exists(path):
        abort(404)
    
    with open(path) as f:
        results = json.load(f)
    
    # Create PDF
    pdf_name = resfile.replace('.json', '.pdf')
    pdf_path = os.path.join(app.config['RESULT_FOLDER'], pdf_name)
    
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter
    x = 40
    y = height - 40
    line_height = 14
    
    def check_page(current_y, needed_space=30):
        """Start new page if needed"""
        if current_y < needed_space:
            c.showPage()
            return height - 40
        return current_y
    
    # Title
    c.setFont('Helvetica-Bold', 18)
    c.drawString(x, y, 'Network Anomaly Detection Report')
    y -= 30
    
    # Metadata
    c.setFont('Helvetica', 10)
    c.drawString(x, y, f'Result file: {resfile}')
    y -= line_height
    c.drawString(x, y, f'Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}')
    y -= 25
    
    # Summary Statistics
    c.setFont('Helvetica-Bold', 14)
    c.drawString(x, y, 'Summary Statistics')
    y -= 20
    
    c.setFont('Helvetica', 10)
    stats_data = [
        ('Total Packets', results.get('packets', '-')),
        ('Total Flows', results.get('flows', '-')),
        ('Internal IPs', results.get('internal_ips', '-')),
    ]
    
    stats = results.get('stats', {})
    if stats:
        stats_data.extend([
            ('Duration', f"{stats.get('duration', 0):.2f}s"),
            ('Packet Rate', f"{stats.get('packets_per_second', 0):.2f} pkt/s"),
            ('Avg Packet Size', f"{stats.get('avg_packet_size', 0):.0f} bytes"),
            ('Median Packet Size', f"{stats.get('median_packet_size', 0):.0f} bytes"),
        ])
    
    for label, value in stats_data:
        y = check_page(y)
        c.drawString(x, y, f'{label}: {value}')
        y -= line_height
    
    y -= 10
    
    # Protocol Distribution
    if stats.get('protocol_distribution'):
        y = check_page(y, 60)
        c.setFont('Helvetica-Bold', 12)
        c.drawString(x, y, 'Protocol Distribution')
        y -= 16
        
        c.setFont('Helvetica', 9)
        for proto, count in stats['protocol_distribution'].items():
            y = check_page(y)
            pct = (count / results.get('packets', 1)) * 100
            c.drawString(x + 10, y, f'{proto}: {count} ({pct:.1f}%)')
            y -= line_height
    
    y -= 10
    
    # Anomalies Summary
    y = check_page(y, 60)
    c.setFont('Helvetica-Bold', 14)
    c.drawString(x, y, 'Detected Anomalies')
    y -= 20
    
    anomalies = results.get('anomalies', {})
    anomaly_categories = [
        ('port_scanning', 'Port Scanning'),
        ('syn_floods', 'SYN Flood Attacks'),
        ('data_exfiltration', 'Data Exfiltration'),
        ('beaconing', 'C2 Beaconing'),
        ('dns_tunneling', 'DNS Tunneling'),
        ('icmp_tunneling', 'ICMP Tunneling'),
        ('slowloris', 'Slowloris Attacks'),
        ('fragmentation', 'Fragmentation Attacks'),
        ('protocol_anomalies', 'Protocol Anomalies'),
    ]
    
    total_anomalies = 0
    c.setFont('Helvetica', 10)
    
    for key, label in anomaly_categories:
        items = anomalies.get(key, [])
        count = len(items) if isinstance(items, list) else 0
        total_anomalies += count
        
        if count > 0:
            y = check_page(y)
            c.drawString(x, y, f'• {label}: {count} detected')
            y -= line_height
    
    if total_anomalies == 0:
        y = check_page(y)
        c.drawString(x, y, 'No significant anomalies detected')
        y -= line_height
    
    y -= 20
    
    # Detailed Anomalies (top items from each category)
    for key, label in anomaly_categories:
        items = anomalies.get(key, [])
        if not isinstance(items, list) or len(items) == 0:
            continue
        
        y = check_page(y, 80)
        c.setFont('Helvetica-Bold', 12)
        c.drawString(x, y, f'{label} Details')
        y -= 16
        
        c.setFont('Helvetica', 8)
        
        # Show top 3 items
        for i, item in enumerate(items[:3]):
            y = check_page(y, 40)
            
            if key == 'port_scanning':
                c.drawString(x + 10, y, f"Source: {item.get('src_ip', 'N/A')}")
                y -= 12
                c.drawString(x + 10, y, f"  Ports: {item.get('port_count', 0)}, Rate: {item.get('scan_rate', 0):.1f} ports/s")
                y -= 12
            
            elif key == 'data_exfiltration':
                c.drawString(x + 10, y, f"{item.get('flow', 'N/A')} [{item.get('confidence', 'MEDIUM')}]")
                y -= 12
                c.drawString(x + 10, y, f"  Volume: {item.get('total_bytes', 0)/1024/1024:.2f} MB, Rate: {item.get('byte_rate', 0)/1024:.1f} KB/s")
                y -= 12
            
            elif key == 'beaconing':
                c.drawString(x + 10, y, f"{item.get('flow', 'N/A')} [{item.get('confidence', 'MEDIUM')}]")
                y -= 12
                c.drawString(x + 10, y, f"  Interval: {item.get('mean_interval', 0):.2f}s, Regularity: {item.get('regularity_score', 0):.3f}")
                y -= 12
            
            elif key == 'dns_tunneling':
                c.drawString(x + 10, y, f"{item.get('flow', 'N/A')}")
                y -= 12
                c.drawString(x + 10, y, f"  Query rate: {item.get('query_rate', 0):.1f} qps, Total: {item.get('total_queries', 0)}")
                y -= 12
            
            else:
                # Generic display
                c.drawString(x + 10, y, f"{str(item)[:100]}")
                y -= 12
        
        if len(items) > 3:
            y = check_page(y)
            c.drawString(x + 10, y, f"... and {len(items) - 3} more")
            y -= 12
        
        y -= 10
    
    c.save()
    return send_from_directory(app.config['RESULT_FOLDER'], pdf_name, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)