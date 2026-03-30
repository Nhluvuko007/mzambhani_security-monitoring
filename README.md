# 🛡️ MZAMBHANI: Full-Stack Security Monitoring & Threat Intelligence

**MZAMBHANI-SOC** is a multi-tier security platform designed to bridge the gap between low-level system monitoring and high-level analyst investigation. It combines real-time log analysis with a secure, role-based MERN dashboard for incident response and threat intelligence.

---

## 🌟 Key Features

* **Real-Time Log Ingestion (Python):**
Monitors system `auth.log` files using Regex pattern matching to detect Brute-Force attack signatures.
* **Role-Based Access Control (RBAC):**
Implements **JWT (JSON Web Tokens)** to strictly separate Public User tools from Restricted Admin security logs.
* **Threat Intelligence Integration:**
Features "Phish-Tank," a URL investigator powered by the **VirusTotal API v3** for real-time reputation and malware checks.
* **Full-Stack Architecture (MERN):**
Utilizes **MongoDB Atlas** for persistent threat storage and a **React** "Dim Mode" dashboard for high-visibility analysis.
* **Automated Incident Response:**
Triggers immediate **Discord Webhook** alerts and local blacklisting when attack thresholds are exceeded.

---

## 🛠️ Tech Stack

| Component | Technology |
| :--- | :--- |
| **Frontend** | React.js, Bootstrap 5 (Dim Mode), Lucide-React, Axios |
| **Backend** | Node.js, Express.js, JWT (Stateless Auth), Bcrypt.js |
| **Database** | MongoDB Atlas (Cloud-native) |
| **Security Engine** | Python 3.13.12 (Regex, Real-time I/O, Requests) |
| **External APIs** | VirusTotal API v3, Discord Webhook API |

---

## 🏗️ System Architecture

1. **Detection Layer:**
A Python script tails system logs. When a Brute-Force pattern is matched, it pushes the event metadata to the MongoDB cloud.
2. **API Layer:**
A Node.js server acts as the gatekeeper, requiring a valid JWT for any request to the `/api/alerts` (Admin) endpoint.
3. **Presentation Layer:** * **User View:**
Access to the Phish-Tank URL scanner and public scan history.

* **Admin View:**
Restricted dashboard showing live Brute-Force logs, source IPs, and attack severity.

---

## 📋 Installation & Setup

1. **Clone the repository:**

2. **Install dependencies:**

**In the terminal of your project(main folder)**
Bash
pip install requests
pip install python-dotenv

**create a .env file:**
discord_webhook_url=your_discord_webhook_URL
VT_API_KEY=your_virustotal_api_key
MONGO_URI=your_mongoDB_URI

MONGO_USER=name_of_your_DB_user(atlas)
MONGO_PASS=password_of_your_DB(atlas)
MONGO_CLUSTER=cluster_of_your_DB(atlas)

**Prepare the Log File:**
Ensure auth.log exists in the log_file folder that's in the root directory (the script will create an empty one if missing).

**Start Python Monitoring Engine:**
python monitor.py

---

### 1. Backend Configuration

Navigate to the `/backend` folder and create a `.env` file:

PORT=5000
JWT_SECRET=your_secret_key
VT_API_KEY=your_virustotal_api_key
ADMIN_USER=username_for_your_admin
ADMIN_PASS=password_for_your_admin

DB_USER=name_of_your_DB_user(atlas)
DB_PASS=password_of_your_DB(atlas)
DB_CLUSTER=cluster_for_your_DB(atlas_URI)
DB_NAME=name_of_your_DB

### 2. Run the Platform

**Start Backend:**

Bash
cd backend
npm install
node server.js

**Start Frontend:**

Bash
cd frontend
npm install
npm run dev

### 🚦Usage & Testing

### 🛡️ Phish-Tank (Public Utility)

Input any URL (e.g.,https://google.com) into the search bar. The backend Base64-encodes the URL, queries the VirusTotal API, and returns the real-time engine detection count.

### 🚨 Admin Dashboard (Restricted)

Authenticate using the credentials set in your .env. Once a valid JWT is issued, the LIVE_THREAT_FEED will unlock, showing the brute-force logs stored in MongoDB.

### 🧪 Simulating a Threat

To test the detection engine, append 3 failed attempts to the log file (auth.log):

**Open a separate text editor and open the auth.log file**
run the attempt below (hit enter and save)
Mar 17 22:00:00 server sshd: Failed password for root from 192.168.1.1

run the attempt below for accepted (hit enter and save)
Mar 17 22:00:00 server sshd[124]: Accepted password for admin from 127.0.0.1 port 22 ssh2

The Python script will detect this instantly, update the database, and the Admin Dashboard will reflect the new alert, and an alert is sent to Discord and the IP is blacklisted in blacklist.jsonl.

### 💡 Security Principles Applied

Least Privilege: Sensitive system logs are hidden behind cryptographic authorization (JWT).

API Abstraction: Critical API keys (VirusTotal/Discord) are stored server-side to prevent client-side exposure.

Data Integrity: Implemented Regex validation and error handling to ensure log data is parsed accurately before storage.

---

### Developed by Mzambhani | Cybersecurity Portfolio Project 2026
