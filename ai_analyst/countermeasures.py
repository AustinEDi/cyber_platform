# Built-in countermeasure lookups, extensible for future LLM enhancement.

COUNTERMEASURES = {
    "block_ip": "Block IP {ip} at the firewall (iptables -A INPUT -s {ip} -j DROP).",
    "patch_cve": "Apply vendor patch for {cve}. Check vendor advisory and schedule maintenance.",
    "disable_powershell": "Restrict PowerShell usage: enable Constrained Language Mode and Script Block Logging.",
    "isolate_host": "Isolate host {hostname} from network immediately. Disable its switch port or unplug.",
    "reset_credentials": "Force password reset for affected user accounts on {hostname}.",
    "enable_logging": "Increase logging verbosity on {hostname} and forward logs to SIEM.",
}

def get_countermeasure(action, **kwargs):
    template = COUNTERMEASURES.get(action)
    if template:
        return template.format(**kwargs)
    return f"No built-in countermeasure for action '{action}'."
