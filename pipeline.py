import time
import db

# 1. Update parser import based on which file holds your function:
from parse import parse_log_line  # or 'from parse_log_line import parse_log_line'

# 2. Update engine imports with exact case-sensitive filenames:
from rulEngine import BruteForceDetector
from MLEngine import AnomalyDetectorML
LOG_FILE = "auth.log"

def run_siem_pipeline():
    # 1. Initialize DB
    db.init_db()
    
    # 2. Instantiate Engines
    rule_engine = BruteForceDetector(threshold=5, window_seconds=60)
    ml_engine = AnomalyDetectorML()

    print(" SIEM-Lite Ingestion Engine Active. Tailing log file...")

    with open(LOG_FILE, "a+") as f:
        # Move file pointer to end of file for live tailing
        f.seek(0, 2)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            # Step A: Parse log line
            event = parse_log_line(line)
            if not event:
                continue

            # Step B: Rule Engine Check (Brute-Force Thresholds)
            rule_alert = rule_engine.process_event(event)
            if rule_alert:
                db.insert_alert(
                    ip=event['ip'],
                    username=event['user'],
                    alert_type="RULE_BRUTE_FORCE",
                    severity=rule_alert['severity'],
                    message=rule_alert['message']
                )
                print(f" [RULE ALERT] {rule_alert['message']}")

            # Step C: ML Anomaly Check (Behavioral Deviations)
            # (Assuming ml_engine has been pre-trained or handles real-time scoring)
            if ml_engine.is_trained:
                is_anomaly = ml_engine.predict_event(event)
                if is_anomaly:
                    db.insert_alert(
                        ip=event['ip'],
                        username=event['user'],
                        alert_type="ML_ANOMALY",
                        severity="MEDIUM",
                        message=f"Unusual login pattern detected for user '{event['user']}' from {event['ip']}"
                    )
                    print(f" [ML ALERT] Anomaly detected for {event['ip']}")

if __name__ == "__main__":
    run_siem_pipeline()
