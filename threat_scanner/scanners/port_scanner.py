import socket
from datetime import datetime, timezone
from scanner_framework import Scanner

class PortScanner(Scanner):
    def run(self):
        targets = self.config.get("targets", ["localhost"])
        ports = self.config.get("ports", [22, 80, 443, 445])
        severity_map = self.config.get("severity_by_port", {})

        events = []
        for host in targets:
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    if result == 0:
                        severity = severity_map.get(str(port), "low")
                        details = f"Open port {port}/tcp on {host}"
                        events.append({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "source_host": host,
                            "user": "",
                            "event_type": "PortScan",
                            "alert_severity": severity,
                            "details": details
                        })
                        print(f"[+] {details} - severity: {severity}")
                except:
                    pass
        return events
