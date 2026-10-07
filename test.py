import db, time, random

ips = ["192.168.1.50", "45.33.32.156", "185.220.101.5"]
users = ["admin", "root", "user1"]

for _ in range(10):
    db.insert_alert(
        ip=random.choice(ips),
        username=random.choice(users),
        alert_type="BRUTE_FORCE",
        severity=random.choice(["HIGH", "CRITICAL"]),
        message="Failed SSH password threshold exceeded (>5 logins/min)"
    )
    time.sleep(2)
