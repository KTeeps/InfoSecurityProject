How to run the project:

Without web application:
1. Git clone the repository
2. Download the required libraries: scapy, dpkt, numpy
3. Run the anomaly_detector.py script: python3 anomaly_detector.py [filename of .pcap to be analyzed] -- This is
the core of our project
5. Run: ./testall.py to test anomaly_detector.py
6. Run: ./pcap_generator.py to generate artificial .pcap files

With web application:
1. Git clone the repository
2. Download the required libraries: scapy, dpkt, numpy
3. Run: python3 ./app.py
4. Follow IP Address to a browser to view
5. Import .pcap file to see results
