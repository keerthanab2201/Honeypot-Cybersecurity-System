import csv #for dataset
import os
import socket #used to create raw sockets and capture pkts
import struct #unpacks raw binary data(pkt headers) into readable forms
import joblib #loads trained ai model
import subprocess #automatic ip address blocking

# === Load the AI model === (models tells us if a pkt is normal or suspicious based on past training)
model = joblib.load("ai_model.pkl")

# === Unpack the IP header === (first 20 bytes of data)
def parse_ip_header(data): 
    ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20]) 
    version_ihl = ip_header[0] #holds IP version and internet header length
    version = version_ihl >> 4 #extract IP version using bitwise operator
    ihl = version_ihl & 0xF #extract IHL using bitwise operator
    total_length = ip_header[2] #extracts total pkt length
    protocol = ip_header[6] #extracts type of protocol(e.g. tcp)
    src_ip = socket.inet_ntoa(ip_header[8]) #source IP address
    dst_ip = socket.inet_ntoa(ip_header[9]) #destination IP address
    return {
        'version': version,
        'ihl': ihl,
        'total_length': total_length,
        'protocol': protocol,
        'src_ip': src_ip,
        'dst_ip': dst_ip
    }

# === Unpack the TCP header === (20 bytes after IP header) 
def parse_tcp_header(data):
    tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
    src_port = tcp_header[0] #extract source port
    dst_port = tcp_header[1] #exttract destination port
    offset_reserved = tcp_header[4]
    flags = tcp_header[5] #extract individual flags using bitwise operations
    flag_bits = {
        "URG": (flags & 32) >> 5,
        "ACK": (flags & 16) >> 4,
        "PSH": (flags & 8) >> 3,
        "RST": (flags & 4) >> 2,
        "SYN": (flags & 2) >> 1,
        "FIN": flags & 1
    }
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'flags': flag_bits
    }

# === Create and configure the raw socket ===(listens for TCP pkts on all interfaces) 
raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
raw_socket.bind(("0.0.0.0", 0))
raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) #IP_HDRINCL = 1 tells it to include the IP header in captured data

print("🧠 AI-enhanced Honeypot is running...\n")

# === initialise csv file === (builds dataset of every pkt captured by sniffer- later used to train AI and analyse traffic)
csv_filename = "packet_log.csv"
file_exists = os.path.isfile(csv_filename)
#open file in append mode- adds new rows of data to the file
csv_file = open(csv_filename, mode='a', newline='')
csv_writer = csv.writer(csv_file) #writes lists to file as CSV rows
#create a header(column names)
if not file_exists:
    csv_writer.writerow([
        "src_ip", "dst_ip", "src_port", "dst_port",
        "SYN", "ACK", "FIN", "packet_size", "label"
        #these are extracted each time a pkt is captured
    ])

# === Block suspicious IP addresses === (if AI detects suspicious pkt)
def block_ip(ip_address):
    print(f"⛔ Blocking suspicious IP: {ip_address}")
    command = f"iptables -A INPUT -s {ip_address} -j DROP"
    try:
        subprocess.run(command.split(), check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip_address}: {e}")


while True: #infinite loop that listens for incoming pkts
    packet, addr = raw_socket.recvfrom(65535) #grabs a full pkt upto 65535 bytes

    # === Parse IP and TCP headers ===
    ip_info = parse_ip_header(packet[:20])
    ip_header_length = ip_info['ihl'] * 4
    tcp_info = parse_tcp_header(packet[ip_header_length:ip_header_length+20])

    # === Convert IPs to numbers for AI model ===
    def ip_to_int(ip):
        return int("".join(f"{int(octet):03}" for octet in ip.split(".")))

    # === Run the AI model on pkt data ===
    features = [[
        ip_to_int(ip_info["src_ip"]),
        ip_to_int(ip_info["dst_ip"]),
        tcp_info["src_port"],
        tcp_info["dst_port"],
        tcp_info["flags"]["SYN"],
        tcp_info["flags"]["ACK"],
        tcp_info["flags"]["FIN"],
        ip_info["total_length"]
    ]]

    prediction = model.predict(features)[0] #classifies the pkt-> 1(suspicious) or 0(normal)

    # === Print packet info with AI decision ===
    print(f"📦 Packet Received:")
    print(f"   From IP     : {ip_info['src_ip']}:{tcp_info['src_port']}")
    print(f"   To IP       : {ip_info['dst_ip']}:{tcp_info['dst_port']}")
    print(f"   Flags       : {', '.join([k for k, v in tcp_info['flags'].items() if v])}")
    print(f"   Size        : {ip_info['total_length']} bytes")

    if prediction == 1:
        print("⚠️  [ALERT] Suspicious Packet Detected!\n")
        block_ip(ip_info["src_ip"])  # automatically block this IP

    else:
        print("✅ Normal Traffic\n")

    # === after each pkt, log data in csv file
    # Convert IPs to numeric form for ML features
    def ip_to_int(ip):
        return int("".join(f"{int(octet):03}" for octet in ip.split(".")))
    # Log the data with label (manually assume 0 for now)
    csv_writer.writerow([
        ip_to_int(ip_info["src_ip"]),
        ip_to_int(ip_info["dst_ip"]),
        tcp_info["src_port"],
        tcp_info["dst_port"],
        tcp_info["flags"]["SYN"],
        tcp_info["flags"]["ACK"],
        tcp_info["flags"]["FIN"],
        ip_info["total_length"],
        0  # Label it as 0 (normal) by default
])

