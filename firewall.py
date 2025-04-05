import psutil
import json
import socket
import time
import tkinter as tk
from tkinter import scrolledtext
import threading
import os

# Load firewall rules from JSON file
def load_firewall_rules():
    try:
        with open("firewall_rules.json", "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

# Save logs to JSON file safely
def log_traffic(log_entry):
    logs = []
    if os.path.exists("traffic_logs.json"):
        try:
            with open("traffic_logs.json", "r") as file:
                logs = json.load(file)
        except json.JSONDecodeError:
            # Backup corrupted file
            os.rename("traffic_logs.json", "traffic_logs_corrupted.json")
            logs = []

    logs.append(log_entry)
    with open("traffic_logs.json", "w") as file:
        json.dump(logs, file, indent=4)

# Monitor network connections
def monitor_traffic(log_box):
    rules = load_firewall_rules()
    while True:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == "ESTABLISHED" and conn.raddr:
                ip, port = conn.raddr
                try:
                    process = psutil.Process(conn.pid) if conn.pid else None
                    app_name = process.name() if process else "Unknown"
                except Exception:
                    app_name = "Unknown"

                allowed_ips = rules.get(app_name, {}).get("allowed_ips", [])
                if ip not in allowed_ips:
                    log_message = f"BLOCKED: {app_name} tried to access {ip}:{port}\n"
                    log_traffic({"app": app_name, "ip": ip, "port": port, "status": "blocked"})
                else:
                    log_message = f"ALLOWED: {app_name} accessed {ip}:{port}\n"
                    log_traffic({"app": app_name, "ip": ip, "port": port, "status": "allowed"})

                log_box.insert(tk.END, log_message)
                log_box.see(tk.END)

        time.sleep(5)

# Start monitoring in a separate thread
def start_monitoring(log_box):
    thread = threading.Thread(target=monitor_traffic, args=(log_box,), daemon=True)
    thread.start()

# GUI for firewall
def firewall_ui():
    root = tk.Tk()
    root.title("Simple Application Firewall")

    log_box = scrolledtext.ScrolledText(root, width=80, height=20)
    log_box.pack()

    start_button = tk.Button(root, text="Start Monitoring", command=lambda: start_monitoring(log_box))
    start_button.pack()

    root.mainloop()

if __name__ == "__main__":
    firewall_ui()