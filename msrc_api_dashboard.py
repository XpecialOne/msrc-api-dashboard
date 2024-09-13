import streamlit as st
import requests
import pandas as pd
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import json
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt

BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/"
HEADERS = {"Accept": "application/json"}
DATA_DIR = Path("msrc_data")
CVSS_THRESHOLD = 8.0
MSRC_BASE_URL = "https://msrc.microsoft.com/update-guide/vulnerability/"

# Function to load JSON data
def load_json_data(file_path: Path) -> dict:
    try:
        with file_path.open("r") as file:
            return json.load(file)
    except FileNotFoundError:
        st.error(f"File not found: {file_path}")
    except json.JSONDecodeError:
        st.error(f"Error decoding JSON from {file_path}")
    return {}

# Function to ensure directory exists
def ensure_directory_exists(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)

# Retrieve all summaries
def retrieve_all_summaries():
    endpoint = f"{BASE_URL}updates"
    try:
        response = requests.get(endpoint, headers=HEADERS)
        response.raise_for_status()
        return response.json().get("value", [])
    except requests.HTTPError as e:
        st.error(f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
    except requests.RequestException as e:
        st.error(f"An error occurred: {e}")
    return []

# Retrieve and store data
def retrieve_and_store_data():
    ensure_directory_exists(DATA_DIR)
    summaries = retrieve_all_summaries()
    tracked_months = []

    with requests.Session() as session:
        for summary in summaries:
            month_id = summary["ID"]
            file_path = DATA_DIR / f"{month_id}.json"
            if not file_path.exists():
                try:
                    response = session.get(f"{BASE_URL}cvrf/{month_id}", headers=HEADERS)
                    response.raise_for_status()
                    with file_path.open("w") as file:
                        json.dump(response.json(), file)
                    st.success(f"Stored data for {month_id}")
                except requests.HTTPError as e:
                    st.error(f"HTTP error occurred for {month_id}: {e.response.status_code} - {e.response.text}")
                except requests.RequestException as e:
                    st.error(f"An error occurred while retrieving data for {month_id}: {e}")
            tracked_months.append(month_id)

    all_months = {summary["ID"] for summary in summaries}
    missing_months = all_months - set(tracked_months)
    if not missing_months:
        st.success("Data fully updated.")
    else:
        st.warning(f"Missing data for months: {', '.join(missing_months)}")

# Extract severity and exploitation status
def extract_severity_and_exploitation(vuln):
    severity = "Unknown"
    exploited_status = "Not Exploited"
    
    # First, attempt to extract from CVSSScoreSets
    cvss_score = get_cvss_score(vuln)
    if cvss_score != "N/A":
        if cvss_score >= 9.0:
            severity = "Critical"
        elif cvss_score >= 7.0:
            severity = "High"
        elif cvss_score >= 4.0:
            severity = "Medium"
        else:
            severity = "Low"
    
    # Next, check for exploitation status in Threats section
    for threat in vuln.get("Threats", []):
        description = threat.get("Description", {}).get("Value", "")
        if "Exploited:Yes" in description:
            exploited_status = "Exploited"
        if "Severity:" in description:
            severity = description.split("Severity:")[1].split()[0]

    return severity, exploited_status

# Get CVSS score
def get_cvss_score(vuln):
    cvss_sets = vuln.get("CVSSScoreSets")
    if cvss_sets:
        try:
            return float(cvss_sets[0].get("BaseScore"))
        except (ValueError, TypeError):
            return "N/A"
    return "N/A"

# Fetch vulnerabilities for a specific month and year
def get_month_vulnerabilities(year, month):
    file_path = DATA_DIR / f"{year}-{month}.json"
    if not file_path.exists():
        st.warning(f"No data found for {month} {year}.")
        return None
    data = load_json_data(file_path)
    return data.get("Vulnerability", [])

# Display detailed CVE information
def display_cve_details(vuln):
    st.subheader(f"Details for {vuln.get('CVE', 'N/A')}")
    st.write(f"**Title:** {vuln.get('Title', {}).get('Value', 'N/A')}")
    cvss_sets = vuln.get("CVSSScoreSets", [{}])[0]
    st.write(f"**CVSS Score:** {cvss_sets.get('BaseScore', 'N/A')}")
    st.write(f"**Attack Vector:** {cvss_sets.get('Vector', 'N/A')}")

    severity, exploited_status = extract_severity_and_exploitation(vuln)
    st.write(f"**Severity:** {severity}")
    st.write(f"**Exploited Status:** {exploited_status}")

    # Add Microsoft advisory link
    cve_id = vuln.get("CVE", "N/A")
    if cve_id != "N/A":
        advisory_url = f"{MSRC_BASE_URL}{cve_id}"
        st.write(f"**Microsoft Advisory Link:** [Link to Advisory]({advisory_url})")

    # Display remediation URL
    for rem in vuln.get("Remediations", []):
        if rem.get("URL"):
            st.write(f"**Remediation URL:** [Link]({rem.get('URL', 'N/A')})")
            break

    # Display acknowledgments
    acknowledgments = ", ".join([ack_dict.get("Value", "") for ack in vuln.get("Acknowledgments", []) for ack_dict in ack.get("Name", [])])
    st.write(f"**Acknowledgments:** {acknowledgments}")

# Function to show vulnerabilities in a month
def display_monthly_data(year, month, min_cvss, severity_filter, exploit_filter):
    vulnerabilities = get_month_vulnerabilities(year, month)
    if vulnerabilities:
        # If no severity filter is selected, consider all severities
        if not severity_filter:
            severity_filter = ["Critical", "High", "Medium", "Low"]

        # If no exploit filter is selected, consider both exploited and not exploited
        if not exploit_filter:
            exploit_filter = ["Exploited", "Not Exploited"]

        # Filter by CVSS, severity, and exploit availability
        vulnerabilities_filtered = [
            vuln for vuln in vulnerabilities 
            if (get_cvss_score(vuln) != "N/A" and float(get_cvss_score(vuln)) >= min_cvss) 
            and extract_severity_and_exploitation(vuln)[0] in severity_filter
            and extract_severity_and_exploitation(vuln)[1] in exploit_filter
        ]

        st.subheader(f"Vulnerabilities for {month} {year} (Min CVSS: {min_cvss})")
        
        # Create a table for vulnerabilities
        vuln_table = []
        for vuln in vulnerabilities_filtered:
            cve = vuln.get("CVE", "")
            title = vuln.get("Title", {}).get("Value", "")
            cvss_score = get_cvss_score(vuln)
            severity, exploited_status = extract_severity_and_exploitation(vuln)
            advisory_url = f"{MSRC_BASE_URL}{cve}" if cve else ""
            vuln_table.append([cve, title, cvss_score, severity, exploited_status, advisory_url])

        df = pd.DataFrame(vuln_table, columns=["CVE", "Title", "CVSS", "Severity", "Exploited", "Advisory Link"])
        df["Advisory Link"] = df["Advisory Link"].apply(lambda x: f"[Link]({x})" if x else "")

        st.write(df.to_markdown(index=False), unsafe_allow_html=True)

        # Select a CVE to view details
        selected_cve = st.selectbox("Select a CVE for details", df["CVE"])
        if selected_cve:
            for vuln in vulnerabilities_filtered:
                if vuln.get("CVE", "") == selected_cve:
                    display_cve_details(vuln)
                    break

# Trend visualization
def display_trend(vulnerabilities, selected_period):
    # Create a DataFrame with the trend data
    trend_data = pd.DataFrame(vulnerabilities, columns=["Date", "Count"])
    trend_data = trend_data.set_index("Date")
    st.line_chart(trend_data)

# Function to generate trend data for the selected period
def get_trend_data(start_year, end_year, min_cvss, severity_filter, exploit_filter):
    trend_data = []
    for year in range(start_year, end_year + 1):
        for month in ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]:
            vulnerabilities = get_month_vulnerabilities(year, month)
            if vulnerabilities:
                # If no severity filter is selected, consider all severities
                if not severity_filter:
                    severity_filter = ["Critical", "High", "Medium", "Low"]

                # If no exploit filter is selected, consider both exploited and not exploited
                if not exploit_filter:
                    exploit_filter = ["Exploited", "Not Exploited"]

                filtered_vulns = [
                    vuln for vuln in vulnerabilities 
                    if (get_cvss_score(vuln) != "N/A" and float(get_cvss_score(vuln)) >= min_cvss) 
                    and extract_severity_and_exploitation(vuln)[0] in severity_filter
                    and extract_severity_and_exploitation(vuln)[1] in exploit_filter
                ]
                trend_data.append([f"{year}-{month}", len(filtered_vulns)])
    return trend_data

# Main Streamlit interface
def main():
    st.title("Microsoft Patch releases Dashboard by SoufianeM")

    # Sidebar for page selection, setting default to Vulnerability Data
    page = st.sidebar.selectbox("Choose a page", ["Vulnerability Data", "Trend Analysis"])

    current_year = datetime.now().year
    year_range = list(range(2017, current_year + 1))  # You can adjust the start year

    if page == "Trend Analysis":
        st.header("Trend Analysis")

        # Select the period for trend visualization
        start_year = st.selectbox("Select Start Year", year_range)
        end_year = st.selectbox("Select End Year", year_range)

        # Filters for CVSS, severity, and exploit availability
        min_cvss = st.slider("Minimum CVSS Score", 0.0, 10.0, 0.0)
        severity_filter = st.multiselect("Select Severity", ["Critical", "High", "Medium", "Low"])
        exploit_filter = st.multiselect("Exploit Availability", ["Exploited", "Not Exploited"])

        # Display the trend based on the selected period, severity, and exploit availability
        if st.button("Show Trend"):
            trend_data = get_trend_data(start_year, end_year, min_cvss, severity_filter, exploit_filter)
            if trend_data:
                display_trend(trend_data, f"{start_year} to {end_year}")
            else:
                st.warning("No data available for the selected period and filters.")

    elif page == "Vulnerability Data":
        st.header("Vulnerability Data")

        # Button to retrieve and store the latest data
        if st.button("Retrieve and Store Data"):
            retrieve_and_store_data()

        # Select year and month for data display
        year = st.selectbox("Select Year for Detailed View", year_range)
        month = st.selectbox("Select Month", ["All"] + ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])

        # Filters for CVSS, severity, and exploit availability
        min_cvss = st.slider("Minimum CVSS Score", 0.0, 10.0, 8.0)
        severity_filter = st.multiselect("Select Severity", ["Critical", "High", "Medium", "Low"])
        exploit_filter = st.multiselect("Exploit Availability", ["Exploited", "Not Exploited"])

        # Display data based on the selected year and month
        if month == "All":
            trend_data = get_trend_data(year, year, min_cvss, severity_filter, exploit_filter)
            display_trend(trend_data, f"Year: {year}")
        else:
            display_monthly_data(year, month, min_cvss, severity_filter, exploit_filter)

if __name__ == "__main__":
    main()
