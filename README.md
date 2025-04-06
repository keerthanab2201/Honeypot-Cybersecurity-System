# Honeypot-Cybersecurity-System

✅ Captures network packets using raw sockets.
✅ Logs and trains AI to detect unusual traffic.
✅ Uses AI in real time to flag attacks.
✅ Displays attacks in a web dashboard.

Part 1:
-Raw Sockets are a special kind of socket that allows direct access to network packets.
-Unlike normal sockets (used for web or chat apps), they provide low-level access to packet data—like source/destination IP, port numbers, flags, and even payloads.
- Create a raw socket that listens for all incoming TCP packets.
- Print basic details about each packet (IP address, size, etc.).
- Use this as the foundation for logging and AI detection later.

Part 2:
- Load attack data and convert it into numbers.
- Train an AI model to detect abnormal patterns.
- Save the model to use it in real-time detection.
  


