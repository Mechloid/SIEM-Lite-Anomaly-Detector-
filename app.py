import streamlit as st
import pandas as pd
import sqlite3
import time
import plotly.express as px

DB_NAME = "siem_alerts.db"

# Page configuration
st.set_page_config(
    page_title="SIEM-Lite Real-Time Monitor",
    layout="wide"
)

def fetch_data():
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC", conn)
    conn.close()
    return df

# Main Title & Auto-refresh control
st.title("SIEM-Lite Real-Time Log Anomaly Monitor")

# Sidebar Controls
st.sidebar.header("Dashboard Settings")
auto_refresh = st.sidebar.checkbox("Enable Auto-Refresh (3s)", value=True)
severity_filter = st.sidebar.multiselect(
    "Filter Severity", 
    options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
)

# Load Data
df = fetch_data()

if not df.empty:
    # Apply sidebar severity filter
    df_filtered = df[df['severity'].isin(severity_filter)]

    # --- TOP LEVEL METRICS ---
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Alerts", len(df))
    col2.metric("Critical Alerts", len(df[df['severity'] == 'CRITICAL']))
    col3.metric("High Severity", len(df[df['severity'] == 'HIGH']))
    col4.metric("Unique Attacker IPs", df['ip_address'].nunique())

    st.markdown("---")

    # --- CHARTS & VISUALIZATIONS ---
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("Alert Volume by Severity")
        severity_counts = df_filtered['severity'].value_counts().reset_index()
        severity_counts.columns = ['Severity', 'Count']
        fig_pie = px.pie(
            severity_counts, 
            values='Count', 
            names='Severity',
            color='Severity',
            color_discrete_map={'CRITICAL':'red', 'HIGH':'orange', 'MEDIUM':'yellow', 'LOW':'blue'}
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    with chart_col2:
        st.subheader("Top Attacker IPs")
        top_ips = df_filtered['ip_address'].value_counts().head(5).reset_index()
        top_ips.columns = ['IP Address', 'Alert Count']
        fig_bar = px.bar(top_ips, x='IP Address', y='Alert Count', color='Alert Count')
        st.plotly_chart(fig_bar, use_container_width=True)

    # --- REAL-TIME ALERT STREAM TABLE ---
    st.subheader("Live Security Alert Stream")
    
    # Styled dataframe display
    st.dataframe(
        df_filtered[['timestamp', 'severity', 'ip_address', 'username', 'alert_type', 'message']],
        use_container_width=True,
        hide_index=True
    )

else:
    st.info("No security alerts detected in SQLite database yet.")

# Auto-refresh loop logic
if auto_refresh:
    time.sleep(3)
    st.rerun()
