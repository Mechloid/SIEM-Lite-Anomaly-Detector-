from collections import defaultdict
import time

class BruteForceDetector:
    def __init__(self, threshold=5, window_seconds=60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.failed_attempts = defaultdict(list)

    def process_event(self, event):
        if event['status'] == 'Failed':
            ip = event['ip']
            now = time.time()
            
            # Remove timestamps outside time window
            self.failed_attempts[ip] = [t for t in self.failed_attempts[ip] if now - t < self.window_seconds]
            self.failed_attempts[ip].append(now)
            
            # Check threshold
            if len(self.failed_attempts[ip]) >= self.threshold:
                return {
                    'type': 'RULE_ALERT',
                    'severity': 'HIGH',
                    'message': f'Brute force detected from IP {ip} ({len(self.failed_attempts[ip])} failures in {self.window_seconds}s)'
                }
        return None
