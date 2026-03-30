import os
import requests
import time
from pymongo import MongoClient
import urllib.parse
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
API_URL = "https://www.virustotal.com/api/v3/urls"

# Retrieve login credentials for admin from .env 
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

scans_collection = db["url_scans"]


def scan_url(target_url):
    headers = {
        "x-apikey": API_KEY
    }
    
    # Step 1: Submit the URL for analysis
    data = {"url": target_url}
    response = requests.post(API_URL, headers=headers, data=data)
    
    if response.status_code != 200:
        print(f"❌ Error submitting URL: {response.status_code}")
        return

    # Get the analysis ID
    analysis_id = response.json()['data']['id']
    print(f"🔍 Analyzing {target_url}... (This may take a moment)")

    # Step 2: Retrieve the report
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    # Wait a few seconds for VT to finish its work
    time.sleep(5)
    
    report_response = requests.get(report_url, headers=headers)
    # ... after you get the report_response ...
    report_data = report_response.json()
    
    # DEBUG LINES:
    stats = report_data['data']['attributes']['stats']
    print(f"DEBUG STATS: {stats}")
    results = report_response.json()['data']['attributes']['results']
    
    # Step 3: Parse the results
    # Total engines is the sum of all stats
    total_engines = sum(stats.values())
    malicious_count = stats['malicious']

    print(f"\n--- 🛡️ PHISH-TANK REPORT ---")
    print(f"URL: {target_url}")
    print(f"Security Score: {malicious_count}/{total_engines} engines flagged this.")
    
    if malicious_count > 0:
        print("🚨 WARNING: This link is likely a PHISHING attempt!")
    else:
        print("✅ This link appears safe (clean across major engines).")

    # Inside your scan_url function, after getting results:
    scan_record = {
    "url": target_url,
    "malicious_count": malicious_count,
    "total_engines": total_engines,
    "scan_date": time.ctime()
    }
    scans_collection.insert_one(scan_record)

def save_report(url, detections, results):
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"scan_{timestamp}.txt"
    
    with open(filename, "w") as f:
        f.write(f"VIRUSTOTAL SCAN REPORT\n")
        f.write(f"Target URL: {url}\n")
        f.write(f"Detections: {detections}\n")
        f.write("-" * 30 + "\n")
        
        # List the engines that found it malicious
        for engine, data in results.items():
            if data['category'] == 'malicious':
                f.write(f"[🚨] {engine}: {data['result']}\n")
                
    print(f"📄 Detailed report saved as: {filename}")

if __name__ == "__main__":
    link = input("Enter a URL to scan: ")
    scan_url(link)
