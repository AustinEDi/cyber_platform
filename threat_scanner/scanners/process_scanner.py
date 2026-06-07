import subprocess
import platform
from datetime import datetime, timezone
from scanner_framework import Scanner

class ProcessScanner(Scanner):
    def run(self):
        suspicious = self.config.get("suspicious_names", [])
        if not suspicious:
            return []
        system = platform.system()
        cmd = ["tasklist", "/FO", "CSV"] if system == "Windows" else ["ps", "aux"]
        try:
            output = subprocess.check_output(cmd, text=True)
        except Exception as e:
            print(f"[-] Cannot list processes: {e}")
            return []
        events = []
        current_host = platform.node() or "localhost"
        for line in output.splitlines():
            for name in suspicious:
                if name.lower() in line.lower():
                    details = f"Suspicious process matching '{name}' detected on {current_host}"
                    events.append({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "source_host": current_host,
                        "user": "",
                        "event_type": "SuspiciousProcess",
                        "alert_severity": "medium",
                        "details": details
                    })
                    print(f"[+] {details}")
                    break
        return events
