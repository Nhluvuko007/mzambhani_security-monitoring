# 🛡️ Mzambhani: Real-Time Login Security Monitor

**Mzambhani** is a lightweight Python-based security automation tool designed to monitor system authentication logs for brute-force attack patterns. It extracts login metadata in real-time, maintains an internal state of failure counts, and triggers automated alerts via Discord Webhooks and local persistent logging.

---

## 🚀 Key Features

* **Real-Time Log Tailing:** Uses efficient file pointer tracking to monitor logs as they are written, ensuring minimal CPU overhead.
* **Pattern Recognition:** Utilizes advanced Regular Expressions (Regex) to distinguish between `Failed` and `Accepted` login attempts.
* **Automated Incident Response:** Immediately notifies administrators via **Discord Webhooks** when a specific IP exceeds a defined failure threshold.
* **High-Performance Logging:** Records threats in **JSON Lines (.jsonl)** format, allowing for $O(1)$ append operations and easy ingestion by SIEM tools.

---

## 🛠️ Tech Stack

* **Language:** Python 3.13.12
* **Libraries:** `requests` (API Communication), `re` (Pattern Matching), `json` (Data Serialization)
* **DevOps/Security:** Log Rotation handling, Real-time I/O, Discord API Integration

---

## 📋 Installation & Setup

1. **Clone the repository:**

2. **Install dependencies:**

Bash (In the terminal of your project)
pip install requests
pip install python-dotenv

**Configure the Webhook:**
Open monitor.py and replace the WEBHOOK_URL placeholder with your Discord Webhook URL.

Prepare the Log File:
Ensure auth.log exists in the log_file folder that's in the root directory (the script will create an empty one if missing).

**🚦 Usage**
Run the monitor using the Python interpreter:

Bash (In the terminal of your project)
python monitor.py

**Testing the Monitor**
To simulate a brute-force attack, append 3 failed attempts to the log file:

**Open a separate text editor and open the auth.log file** run the attempt below (hit enter and save)
Mar 17 22:00:00 server sshd: Failed password for root from 192.168.1.100

run the attempt below for accepted (hit enter and save)
Mar 17 22:00:00 server sshd[124]: Accepted password for admin from 127.0.0.1 port 22 ssh2

📊 Logic Flow
Watch: The script identifies the end of the auth.log file.

Parse: New lines are scanned for the Failed password pattern.

Count: A defaultdict tracks failures per IP address.

Action: If Count >= 3, an alert is sent to Discord and the IP is blacklisted in blacklist.jsonl.
