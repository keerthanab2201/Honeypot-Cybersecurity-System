import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# Load your labeled CSV
df = pd.read_csv("packets_dataset.csv")

# Convert IPs to numeric (simplified)
df["src_ip"] = df["src_ip"].apply(lambda x: int("".join(x.split("."))))
df["dst_ip"] = df["dst_ip"].apply(lambda x: int("".join(x.split("."))))

# Features and label
X = df[["src_ip", "dst_ip", "src_port", "dst_port", "flag_syn", "flag_ack", "flag_fin", "packet_size"]]
y = df["label"]

# Split and train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "honeypot_ai_model.pkl")

