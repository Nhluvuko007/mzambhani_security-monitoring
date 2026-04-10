import re
import time
import json
import os
import requests
from dotenv import load_dotenv
from pymongo import MongoClient
import urllib.parse
from collections import defaultdict

# Load the variables from .env file
load_dotenv() 

# 1. Configuration
log_file = "log_file/auth.log"
threshold = 3 # Alert after 3 failed attempts

# Get URL for webhook to receive alerts (Your Discord URL)
webhook_url = os.getenv("discord_webhook_url")

# Safety check: Stop the script if the URL is missing
if not webhook_url:
    print("ERROR: discord_webhook_url not found in .env file!")
    exit()

# Retrieve from .env
user = os.getenv("MONGO_USER")
password = os.getenv("MONGO_PASS")
cluster = os.getenv("MONGO_CLUSTER")

# Load MongoDB
safe_user = urllib.parse.quote_plus(user)
safe_pass = urllib.parse.quote_plus(password)

# Construct the URI
MONGO_URI = f"mongodb+srv://{safe_user}:{safe_pass}@{cluster}/?appName=Mzambhani"

try:
    client = MongoClient(MONGO_URI)
    db = client["SecurityDB"]
    # Quick test connection
    client.admin.command('ping')
    print("✅ Successfully connected to MongoDB Atlas!")
except Exception as e:
    print(f"❌ Connection Error: {e}")

alerts_collection = db["alerts"]

# This regex extracts: [Status], [User], and [IP Address]
log_pattern = r"(Failed|Accepted) password for (\w+) from ([\d\.]+)"

# 2. State Tracking
# This dictionary stores how many times each IP has failed
# Example: {"192.168.1.50": 2}

failure_tracker = defaultdict(int)

def send_to_discord(message):
    """Send a formatted message to Discord."""
    payload = {
        "content": message,
        "username": "MzambhaniBot"
    }
    try:
        requests.post(webhook_url, json=payload)
    except Exception as e:
        print(f"Error sending to Discord: {e}")

def trigger_alert(ip, count):
    """Logs the threat and sends a Discord alert."""
    alert_msg = f"[ALERT] Brute force detected from IP: {ip} ({count} failed attempts)"
    print(f"\n{alert_msg}\n")

    # 1. Prepare the Data Object
    alert_data = {
        "ip": ip,
        "attempts": count,
        "timestamp": time.ctime(),
        "type": "Brute Force",
        "severity": "High"
    }

    # 2. Push to MongoDB
    try:
        alerts_collection.insert_one(alert_data)
        print("💾 Alert synced to MongoDB.")
    except Exception as e:
        print(f"❌ MongoDB Sync Error: {e}")

    # Save the bad IP to a 'blacklisted' file
    blacklist_data = {"ip": ip, "reason": "Brute Force", "attempts": count, "timestamp": time.ctime()}
    with open("blacklist.jsonl", "a") as f:
        f.write(json.dumps(blacklist_data) + "\n")

        print(f"IP {ip} has been logged to blacklist.jsonl")

        # Discord alert message
        send_to_discord(alert_msg)

def process_line(line):
    """Analyzes a single line of text for login patterns."""
    print(f"{line.strip()}")
    match = re.search(log_pattern, line)

    if match:
        status, user, ip = match.groups()

        if status == "Failed":
            failure_tracker[ip] += 1
            print(f"{status} attempt from {ip} (User: {user} | Count: {failure_tracker[ip]})")

            # Check id threshold is reached
            if failure_tracker[ip] >= threshold:
                trigger_alert(ip,failure_tracker[ip])

            elif status == "Accepted":
                print(f"Successful login for {user} from {ip}.")
                failure_tracker[ip] = 0 # Reset counter because they logged in successfully

def monitor_log():
    """Main loop that 'tails' the log file in real-time."""
    if not os.path.exists(log_file):
        print(f"Error: {log_file} not found.")
        return
    
    with open(log_file, "r") as f:
        # Move the cursor to the very end of the file to see NEW information(logs)
        f.seek(0, os.SEEK_END)
        last_pos = f.tell()
        print(f"--- Mzambhani is active and Monitoring... ---")

        while True:
                line = f.readline()

                # If there's no new line, wait a moment and try again
                if not line:
                    if os.path.getsize(log_file) < last_pos:
                        # File was cleared or rotated, reset to start 
                        f.seek(0)
                    else:
                        # Wait and try again
                        time.sleep(0.5)
                    last_pos = f.tell()
                    continue

                # If new line is found, process it
                process_line(line)

if __name__ == "__main__":
    monitor_log()
