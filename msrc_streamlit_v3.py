import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go

# Set page configuration
st.set_page_config(page_title="Microsoft Patch Dashboard", page_icon="🛡️", layout="wide")

# Custom CSS to improve the look and feel
st.markdown("""
<style>
    .reportview-container {
        background: #f0f2f6
    }
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    h1, h2, h3 {
        color: #2c3e50;
    }
    .stSelectbox label, .stSlider label {
        color: #2c3e50;
    }
    .stDataFrame {
        border: 1px solid #e0e0e0;
        border-radius: 5px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .stPlotlyChart {
        border: 1px solid #e0e0e0;
        border-radius: 5px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h1 {
        color: #e67e22;
        font-weight: bold;
        text-shadow: 1px 1px 2px #d35400;
    }
    [data-testid="stSidebar"] [data-testid="stSelectbox"] label {
        color: #e67e22;
        font-weight: bold;
        text-shadow: 1px 1px 2px #d35400;
    }
    .logo-text {
        font-family: Arial, sans-serif;
        font-size: 24px;
        font-weight: bold;
        color: #e67e22;
        text-shadow: 1px 1px 2px #d35400;
        padding: 10px;
        border: 2px solid #e67e22;
        border-radius: 10px;
        display: inline-block;
    }
</style>
""", unsafe_allow_html=True)

# Create a simple logo
logo_html = """
<div class="logo-text">SM</div>
"""

# Database connection
DB_PATH = 'vulnerabilities.db'
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Function to fetch Tenable covered CVEs
@st.cache_data
def get_tenable_covered_cves():
    query = "SELECT DISTINCT cve_id FROM tenable_plugins"
    tenable_cves = pd.read_sql_query(query, conn)
    return tenable_cves['cve_id'].tolist()

# Function to fetch vulnerability data using InitialReleaseDate
def fetch_vulnerabilities(year, month, min_cvss, severity_filter, exploit_filter, tenable_filter):
    query = "SELECT * FROM vulnerabilities WHERE 1=1"
    params = []

    # Apply year and month filters using 'InitialReleaseDate'
    try:
        if month != "All":
            query += " AND strftime('%Y', InitialReleaseDate) = ? AND strftime('%m', InitialReleaseDate) = ?"
            params.extend([str(year), f"{int(month):02d}"])
        else:
            query += " AND strftime('%Y', InitialReleaseDate) = ?"
            params.append(str(year))
    except Exception as e:
        st.error(f"Error with date filtering: {e}")
        return pd.DataFrame()  # Return an empty DataFrame if there's an error

    # Apply CVSS filter, ignoring NaN values
    if min_cvss > 0.0:
        query += " AND (cvss_score IS NOT NULL AND cvss_score >= ?)"
        params.append(min_cvss)

    # Apply severity filter
    if severity_filter:
        placeholders = ','.join('?' * len(severity_filter))
        query += f" AND severity IN ({placeholders})"
        params.extend(severity_filter)

    # Apply exploit filter
    if exploit_filter:
        placeholders = ','.join('?' * len(exploit_filter))
        query += f" AND exploited_status IN ({placeholders})"
        params.extend(exploit_filter)

    # Fetch data
    try:
        df = pd.read_sql_query(query, conn, params=params)
    except Exception as e:
        st.error(f"Error fetching data: {e}")
        return pd.DataFrame()  # Return an empty DataFrame if there's an error

    # Rename columns for display
    column_mapping = {
        'cve_id': 'CVE',
        'title': 'Title',
        'cvss_score': 'CVSS',
        'severity': 'Severity',
        'exploited_status': 'Exploit Availability',
        'advisory_link': 'Advisory Link',
        'InitialReleaseDate': 'Disclosure Date',
        'remediation_url': 'Remediation Link'
    }
    
    df = df.rename(columns=column_mapping)

    # Optimize by moving this outside the function and caching it
    tenable_covered_cves = get_tenable_covered_cves()

    # Apply Tenable coverage filter
    if tenable_filter != "All":
        if tenable_filter == "Covered":
            df = df[df['CVE'].isin(tenable_covered_cves)]
        else:
            df = df[~df['CVE'].isin(tenable_covered_cves)]

    # Add Tenable plugin information
    df['Tenable Plugin'] = df['CVE'].apply(lambda cve: get_tenable_plugin_info(cve))

    # Remove the 'last_modified' column if it exists
    if 'last_modified' in df.columns:
        df = df.drop(columns=['last_modified'])

    # Add print statements for debugging
    print(df.columns)
    print(df['Remediation Link'].head())

    return df

@st.cache_data
def get_tenable_plugin_info(cve_id):
    query = "SELECT plugin_id, plugin_url FROM tenable_plugins WHERE cve_id = ?"
    result = pd.read_sql_query(query, conn, params=[cve_id])
    if not result.empty:
        plugin_links = []
        for _, row in result.iterrows():
            plugin_id = row['plugin_id']
            plugin_url = row['plugin_url']
            plugin_links.append(f"[{plugin_id}]({plugin_url})")
        return ", ".join(plugin_links)
    return "Not Covered"

def display_cve_details(cve_data):
    st.subheader(f"Details for {cve_data['CVE']}")
    st.write(f"**Title:** {cve_data['Title']}")
    st.write(f"**CVSS Score:** {cve_data['CVSS']}")
    st.write(f"**Severity:** {cve_data['Severity']}")
    st.write(f"**Exploit Availability:** {cve_data['Exploit Availability']}")
    st.write(f"**Microsoft Advisory Link:** [{cve_data['CVE']}]({cve_data['Advisory Link']})")
    
    # Add a print statement to check the cve_data
    print(cve_data)
    
    if 'Remediation Link' in cve_data and pd.notna(cve_data['Remediation Link']):
        st.write(f"**Remediation Link:** [{cve_data['CVE']} Remediation]({cve_data['Remediation Link']})")
    else:
        st.write("**Remediation Link:** Not available")
    
    st.write("**Tenable Plugin IDs:**")
    st.markdown(cve_data['Tenable Plugin'])

# Function to fetch trend data
@st.cache_data
def fetch_trend_data():
    query = """
    SELECT 
        strftime('%Y-%m', InitialReleaseDate) as date,
        SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as Critical,
        SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as High,
        SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) as Medium,
        SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) as Low,
        SUM(CASE WHEN exploited_status = 'Exploited' THEN 1 ELSE 0 END) as Exploited
    FROM vulnerabilities
    GROUP BY strftime('%Y-%m', InitialReleaseDate)
    ORDER BY date
    """
    df = pd.read_sql_query(query, conn)
    df['date'] = pd.to_datetime(df['date'])
    df['formatted_date'] = df['date'].dt.strftime('%B %Y')
    df['year'] = df['date'].dt.year
    df['month'] = df['date'].dt.strftime('%B')
    return df

# Main Streamlit interface
def main():
    st.title("Microsoft Patch Dashboard")

    # Sidebar with logo and navigation
    st.sidebar.markdown(logo_html, unsafe_allow_html=True)
    st.sidebar.markdown("<h1>Navigation</h1>", unsafe_allow_html=True)
    page = st.sidebar.selectbox("Select Page", ["Vulnerability Data", "Trend Analysis"])

    current_year = datetime.now().year
    year_range = list(range(2018, current_year + 1))

    if page == "Vulnerability Data":
        st.header("Vulnerability Data")

        # Create columns for filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            year = st.selectbox("Select Year", year_range)
            min_cvss = st.slider("Minimum CVSS Score", 0.0, 10.0, 0.0)
        
        with col2:
            month = st.selectbox("Select Month", ["All"] + [f"{i:02d}" for i in range(1, 13)])
            severity_filter = st.multiselect("Select Severity", ["Critical", "High", "Medium", "Low", "Unknown"])
        
        with col3:
            exploit_filter = st.multiselect("Exploit Availability", ["Exploited", "Not Exploited"])
            tenable_filter = st.selectbox("Tenable Coverage", ["All", "Covered", "Not Covered"])

        # Fetch vulnerabilities based on the filters
        df = fetch_vulnerabilities(year, month, min_cvss, severity_filter, exploit_filter, tenable_filter)

        # Display the results
        if not df.empty:
            st.subheader("Vulnerability Table")
            st.dataframe(df)
            
            # Add a dropdown to select a specific CVE
            st.markdown("---")
            selected_cve = st.selectbox("Select a CVE for details", df['CVE'].tolist())
            
            if selected_cve:
                cve_data = df[df['CVE'] == selected_cve].iloc[0].to_dict()
                display_cve_details(cve_data)
            
            # Add a download button for the data
            st.markdown("---")
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                "📥 Download CSV",
                csv,
                "vulnerability_data.csv",
                "text/csv",
                key='download-csv'
            )
        else:
            st.info("No vulnerabilities match the selected filters.")

    elif page == "Trend Analysis":
        st.header("Trend Analysis")
        
        trend_data = fetch_trend_data()
        
        # Add filters
        col1, col2 = st.columns(2)
        with col1:
            severity_filter = st.multiselect(
                "Select Severity",
                ["Critical", "High", "Medium", "Low"],
                default=["Critical", "High", "Medium", "Low"]
            )
        with col2:
            exploit_filter = st.checkbox("Show only exploited vulnerabilities", value=False)
        
        # Apply filters
        filtered_data = trend_data.copy()
        if severity_filter:
            filtered_data = filtered_data[severity_filter + ['date', 'formatted_date', 'year', 'month', 'Exploited']]
        if exploit_filter:
            filtered_data = filtered_data[filtered_data['Exploited'] > 0]
        
        # Create a stacked area chart
        fig = px.area(filtered_data, x='formatted_date', y=severity_filter,
                      title='Vulnerabilities by Severity Over Time',
                      labels={'value': 'Number of Vulnerabilities', 'variable': 'Severity'},
                      color_discrete_map={'Critical': 'red', 'High': 'orange', 'Medium': 'yellow', 'Low': 'green'})
        fig.update_layout(xaxis_title='Date', yaxis_title='Number of Vulnerabilities')
        fig.update_xaxes(tickangle=45)
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Vulnerability Counts by Severity (Click on a year to expand)")

        # Create yearly_data
        yearly_data = filtered_data.groupby('year')[severity_filter + ['Exploited']].sum().reset_index()
        yearly_data = yearly_data.sort_values('year', ascending=False)

        # Display yearly data with expandable monthly details
        for _, year_row in yearly_data.iterrows():
            year = year_row['year']
            with st.expander(f"{year}"):
                # Yearly total
                st.write(f"Total for {year}:")
                st.dataframe(year_row[['year'] + severity_filter + ['Exploited']].to_frame().T.set_index('year'))
                
                # Monthly breakdown
                st.write(f"Monthly breakdown for {year}:")
                monthly_data = filtered_data[filtered_data['year'] == year].sort_values('date')
                monthly_display = monthly_data.set_index('month')[severity_filter + ['Exploited']]
                st.dataframe(monthly_display)

if __name__ == "__main__":
    main()
