How to run the project:

Without web application:
1. Git clone the repository
2. Download the required libraries: scapy, dpkt, numpy, flask
3. Run the anomaly_detector.py script: python3 anomaly_detector.py [filename of .pcap to be analyzed] -- This is
the core of our project
5. Run: ./testall.py to test anomaly_detector.py and see if it accurately detects the anomalies inside the pcap files in the current directory
6. Run: ./pcap_generator.py to generate artificial .pcap files to test

With web application:
1. Git clone the repository
2. Download the required libraries: dpkt, numpy, flask, reportlab
3. Run: python3 ./app.py
4. Follow IP Address to a browser to view
5. Import .pcap file to see results
