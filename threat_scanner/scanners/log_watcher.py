import os
from datetime import datetime, timezone
from scanner_framework import Scanner

class LogWatcher(Scanner):
    def run(self):
        log_file = self.config.get("log_file")
        if not log_file or not os.path.exists(log_file):
            print(f"[-] Log file not found: {log_file}")
            return []
        patterns = self.config.get("patterns", {})
        malicious_ips = self.config.get("malicious_ips", [])
        events = []
        try:
            with open(log_file, "r") as f:
                for line in f:
                    for pattern, severity in patterns.items():
                        if pattern.lower() in line.lower():
                            details = f"Firewall alert: {line.strip()}"
                            events.append({
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "source_host": "firewall",
                                "user": "",
                                "event_type": "FirewallAlert",
                                "alert_severity": severity,
                                "details": details
                            })
                            break
                    for ip in malicious_ips:
                        if ip in line:
                            details = f"Malicious IP {ip} found in log: {line.strip()}"
                            events.append({
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "source_host": "firewall",
                                "user": "",
                                "event_type": "ThreatIntel",
                                "alert_severity": "high",
                                "details": details
                            })
                            break
        except Exception as e:
            print(f"[-] Error reading log: {e}")
            return []
        print(f"[+] Log scan complete. Found {len(events)} events.")
        return events
