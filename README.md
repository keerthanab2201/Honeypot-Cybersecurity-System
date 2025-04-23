# Honeypot-Cybersecurity-System

1) Raw socket sniffer to capture all incoming TCP packets.
2) IP and TCP header parsing to extract: Source IP, Destination IP, Source Port, Destination Port, TCP Flags (SYN, ACK, FIN), Packet size
3) CSV logging of parsed packet data for ML training.
4) AI model integration to classify packets as normal (0) or suspicious (1).
5) Automatic IP blocking using iptables when a packet is marked suspicious.
6) Readable console output showing parsed packet info and AI decisions.


