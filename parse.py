import re
from datetime import datetime

# Regex pattern for auth log entries
LOG_PATTERN = r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>[\w-]+)\s+sshd\[\d+\]:\s+(?P<status>Failed|Accepted)\s+password\s+for\s+(?P<user>\w+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'

def parse_log_line(line):
    match = re.search(LOG_PATTERN, line)
    if match:
        data = match.groupdict()
        return {
            'timestamp': data['timestamp'],
            'host': data['host'],
            'status': data['status'],
            'user': data['user'],
            'ip': data['ip']
        }
    return None
