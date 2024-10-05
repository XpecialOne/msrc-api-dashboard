import requests
import sqlite3
from datetime import datetime
import time
from bs4 import BeautifulSoup
from pathlib import Path
import re
import concurrent.futures
import logging
from tqdm import tqdm  # Add this import

# Constants
BASE_URL = "https://api.msrc.microsoft.com/cvrf/v2.0/"
HEADERS = {"Accept": "application/json"}
DATA_DIR = Path("msrc_data")
TENABLE_CVE_BASE_URL = "https://www.tenable.com/cve/"
TENABLE_PLUGIN_BASE_URL = "https://www.tenable.com/plugins/nessus/"
CACHE_EXPIRATION_DAYS = 7

# Database connection
DB_PATH = 'vulnerabilities.db'
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Regular expression to match 'CVE-' pattern
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+")

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create tables if they don't exist
def create_tables():
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                title TEXT,
                cvss_score REAL,
                severity TEXT,
                exploited_status TEXT,
                advisory_link TEXT,
                InitialReleaseDate TEXT,
                last_modified DATETIME,
                remediation_url TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tenable_plugins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                plugin_id TEXT,
                plugin_url TEXT,
                FOREIGN KEY (cve_id) REFERENCES vulnerabilities (cve_id)
            )
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities (cve_id)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_tenable_plugins_cve_id ON tenable_plugins (cve_id)
        ''')

        conn.commit()
        logging.info("Tables created successfully.")
    except Exception as e:
        logging.error(f"Error creating tables: {e}")

# Function to fetch Microsoft vulnerabilities
def fetch_microsoft_vulnerabilities():
    try:
        updates_url = f"{BASE_URL}updates"
        response = requests.get(updates_url, headers=HEADERS)
        if response.status_code != 200:
            logging.error(f"Failed to retrieve the list of available documents. Status code: {response.status_code}")
            return []

        updates = response.json().get("value", [])
        if not updates:
            logging.info("No updates found.")
            return []

        vulnerabilities = []

        # Add a progress bar for processing updates
        for update in tqdm(updates, desc="Processing updates", unit="update"):
            document_id = update.get("ID")
            document_url = f"{BASE_URL}cvrf/{document_id}"
            response = requests.get(document_url, headers=HEADERS)
            if response.status_code != 200:
                logging.warning(f"Failed to retrieve data for document ID {document_id}. Status code: {response.status_code}")
                continue

            data = response.json()
            initial_release_date = data.get("DocumentTracking", {}).get("InitialReleaseDate", "")
            logging.info(f"Processing document ID {document_id} with InitialReleaseDate: {initial_release_date}")

            vulnerabilities.extend([
                {
                    "cve": vuln.get("CVE"),
                    "title": vuln.get("Title", {}).get("Value", "N/A"),
                    "cvss_score": get_cvss_score(vuln),
                    "severity": extract_severity(vuln),
                    "exploited_status": extract_exploited_status(vuln),
                    "advisory_link": f"https://msrc.microsoft.com/update-guide/vulnerability/{vuln.get('CVE')}",
                    "initial_release_date": initial_release_date,
                    "remediation_url": extract_remediation_url(vuln)  # Add this line
                }
                for vuln in data.get("Vulnerability", [])
            ])
            time.sleep(0.1)  # To avoid hitting rate limits

        return vulnerabilities
    except Exception as e:
        logging.error(f"Error fetching Microsoft vulnerabilities: {e}")
        return []

def get_cvss_score(vuln):
    cvss_sets = vuln.get("CVSSScoreSets")
    if cvss_sets and len(cvss_sets) > 0:
        try:
            base_score = cvss_sets[0].get("BaseScore")
            if base_score:
                return float(base_score)
        except (ValueError, TypeError):
            return None
    return None

def extract_severity(vuln):
    severity = "Unknown"
    cvss_score = get_cvss_score(vuln)
    if cvss_score is not None:
        if cvss_score >= 9.0:
            severity = "Critical"
        elif cvss_score >= 7.0:
            severity = "High"
        elif cvss_score >= 4.0:
            severity = "Medium"
        else:
            severity = "Low"
    return severity

def extract_exploited_status(vuln):
    exploited_status = "Not Exploited"
    for threat in vuln.get("Threats", []):
        description = threat.get("Description", {}).get("Value", "")
        if "Exploited:Yes" in description:
            exploited_status = "Exploited"
    return exploited_status

def extract_remediation_url(vuln):
    for rem in vuln.get("Remediations", []):
        if rem.get("URL"):
            return rem.get("URL")
    return None

# Improved function to fetch Tenable plugin data
def fetch_tenable_plugins(cve_id):
    if not CVE_PATTERN.match(cve_id):
        logging.info(f"Skipping Tenable plugin fetch for {cve_id} as it does not match 'CVE-' pattern.")
        return []

    try:
        url = f"{TENABLE_CVE_BASE_URL}{cve_id}/plugins"
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            logging.warning(f"Failed to fetch Tenable plugins for {cve_id}. Status code: {response.status_code}")
            return []

        soup = BeautifulSoup(response.content, 'html.parser')
        plugin_table = soup.find('tbody')
        if not plugin_table:
            return []

        return [
            (plugin_link.text.strip(), f"{TENABLE_PLUGIN_BASE_URL}{plugin_link.text.strip()}")
            for row in plugin_table.find_all('tr')
            if (plugin_link := row.find('a', class_='no-break')) and plugin_link.text.strip()
        ]
    except Exception as e:
        logging.error(f"Error fetching Tenable plugins for {cve_id}: {e}")
        return []

# Function to process and store vulnerabilities
def process_and_store_vulnerabilities(vulnerabilities):
    try:
        vuln_data = []
        plugin_data = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_cve = {executor.submit(fetch_tenable_plugins, vuln['cve']): vuln for vuln in vulnerabilities if vuln['cve'] and CVE_PATTERN.match(vuln['cve'])}
            
            # Add a progress bar for processing vulnerabilities
            for future in tqdm(concurrent.futures.as_completed(future_to_cve), total=len(future_to_cve), desc="Processing vulnerabilities", unit="vuln"):
                vuln = future_to_cve[future]
                cve_id = vuln['cve']
                plugin_ids = future.result()
                
                vuln_data.append((
                    cve_id, vuln['title'], vuln['cvss_score'], vuln['severity'],
                    vuln['exploited_status'], vuln['advisory_link'],
                    vuln['initial_release_date'], datetime.now(),
                    vuln['remediation_url']  # Add this line
                ))
                
                plugin_data.extend((cve_id, plugin_id, plugin_url) for plugin_id, plugin_url in plugin_ids)

        # Update the SQL query to include the remediation_url column
        cursor.executemany('''
            INSERT OR REPLACE INTO vulnerabilities 
            (cve_id, title, cvss_score, severity, exploited_status, advisory_link, InitialReleaseDate, last_modified, remediation_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', vuln_data)

        # Batch delete existing plugins
        cursor.executemany('DELETE FROM tenable_plugins WHERE cve_id = ?', 
                           [(cve_id,) for cve_id, _, _ in plugin_data])

        # Batch insert new plugin data
        cursor.executemany('''
            INSERT INTO tenable_plugins (cve_id, plugin_id, plugin_url)
            VALUES (?, ?, ?)
        ''', plugin_data)

        conn.commit()
        logging.info("Vulnerabilities processed and stored successfully.")
    except Exception as e:
        logging.error(f"Error processing and storing vulnerabilities: {e}")

def main():
    logging.info("Starting backend data retrieval...")
    create_tables()
    vulnerabilities = fetch_microsoft_vulnerabilities()
    if vulnerabilities:
        logging.info(f"Fetched {len(vulnerabilities)} vulnerabilities.")
        process_and_store_vulnerabilities(vulnerabilities)
    else:
        logging.info("No vulnerabilities to process.")
    logging.info("Data retrieval and storage complete.")

if __name__ == "__main__":
    main()
