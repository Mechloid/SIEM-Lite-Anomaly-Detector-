# SIEM-Lite: Real-Time Log Anomaly & Brute-Force Detector

A lightweight Security Information and Event Management (SIEM) application that ingests SSH/auth logs in real time, processes events through a hybrid detection engine (Rule-based + ML Anomaly Detection), stores alerts in SQLite, and visualizes security metrics on an auto-refreshing Streamlit dashboard.

---

## Architecture Overview

```text
[ Log File / auth.log ] 
          │
          ▼
   [ Stream Engine ]  ──► (Tails new log lines in real-time)
          │
          ▼
   [ Log Parser ]     ──► (Extracts timestamp, IP, user, status via Regex)
          │
          ├──► [ Rule Engine ] ──► (Flags sliding-window brute force attempts)
          │
          └──► [ ML Engine ]   ──► (Flags behavioral anomalies via Isolation Forest)
                                         │
                                         ▼
                                 [ SQLite Database ]
                                         │
                                         ▼
                            [ Streamlit SOC Dashboard ]
```

---

## Project Structure

```text
.
├── app.py              # Streamlit dashboard UI
├── db.py               # SQLite database interface & schema
├── parse.py            # Log line regex extraction module
├── rulEngine.py        # Sliding-window brute force detection engine
├── MLEngine.py         # Isolation Forest ML anomaly detection model
├── StreamEngine.py     # Live log streaming / file tailing engine
├── pipeline.py         # Core execution script tying parser, engines, and DB
├── test.py             # Log generator / attack simulator for testing
├── requirements.txt    # Python dependencies
└── README.md           # Documentation
```

---

## Getting Started

### 1. Prerequisites
Ensure you have **Python 3.10+** installed on your system.

### 2. Installation & Setup

1. **Clone or navigate to your project directory:**
   ```bash
   cd /path/to/Honors_Project
   ```

2. **Create and activate a virtual environment (recommended):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
   *(On Windows, use `venv\Scripts\activate`)*

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🏃 Running the Application

To run the complete system, open **three separate terminal windows** inside the project folder with your virtual environment activated:

### Step 1: Initialize DB & Start the SIEM Pipeline
In **Terminal 1**, run the main ingestion pipeline:
```bash
python pipeline.py
```
*This starts tailing `auth.log` (or target log file) and initializes `siem_alerts.db` if it doesn't exist.*

### Step 2: Launch the Streamlit Dashboard
In **Terminal 2**, start the security monitor UI:
```bash
streamlit run app.py
```
*Open your browser and navigate to `http://localhost:8501` to view the live dashboard.*

### Step 3: Simulate Log Activity & Attacks
In **Terminal 3**, run your log generator or simulate a brute-force SSH attack:
```bash
python test.py
```
*Alternatively, simulate attacks manually by appending directly to `auth.log`:*
```bash
for i in {1..8}; do
  echo "Oct  8 01:15:20 server sshd[1234]: Failed password for root from 185.220.101.5 port 54321 ssh2" >> auth.log
  sleep 0.2
done
```

---

## 📊 Features & Capabilities

- **Rule-Based Brute Force Engine:** Tracks failed login attempts per IP within a custom sliding time window (e.g., >5 failures in 60s).
- **ML Anomaly Detection:** Uses an Unsupervised Isolation Forest model to detect unusual login behavior (frequency spikes, suspicious user target patterns).
- **Real-Time SOC Dashboard:**
  - Dynamic KPI cards (Total Alerts, Critical/High counts, Unique Attacker IPs).
  - Severity distribution pie chart & top attacker IP bar chart.
  - Live auto-refreshing table displaying logged security alerts.
