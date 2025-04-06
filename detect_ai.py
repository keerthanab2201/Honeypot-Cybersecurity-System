import joblib

# Load the model
model = joblib.load("honeypot_ai_model.pkl")

# ... inside your packet loop after parsing:

features = [[
    int("".join(ip_info["src_ip"].split("."))),
    int("".join(ip_info["dst_ip"].split("."))),
    tcp_info["src_port"],
    tcp_info["dst_port"],
    tcp_info["flags"]["SYN"],
    tcp_info["flags"]["ACK"],
    tcp_info["flags"]["FIN"],
    ip_info["total_length"]
]]

prediction = model.predict(features)[0]
if prediction == 1:
    print("⚠️ Suspicious Packet Detected!")
else:
    print("✅ Normal Traffic")
