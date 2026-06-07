#!/usr/bin/env python3
import argparse
import json
from scanner_framework import ingest_events
from scanners.port_scanner import PortScanner
from scanners.process_scanner import ProcessScanner
from scanners.log_watcher import LogWatcher

def load_config(path="scanner_config.json"):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[-] Config file {path} not found. Using defaults.")
        return {}

def main():
    parser = argparse.ArgumentParser(description="Threat Scanner")
    parser.add_argument("--all", action="store_true", help="Run all scanners")
    parser.add_argument("--port", action="store_true", help="Run port scanner")
    parser.add_argument("--process", action="store_true", help="Run process scanner")
    parser.add_argument("--log", nargs="?", const=True, help="Run log watcher (optional: specify log file)")
    parser.add_argument("--target", help="Override port scan target")
    parser.add_argument("--config", default="scanner_config.json", help="Config file path")
    args = parser.parse_args()

    config = load_config(args.config)
    all_events = []

    if args.all or args.port:
        print("[*] Running Port Scanner...")
        port_cfg = config.get("port_scanner", {})
        if args.target:
            port_cfg["targets"] = [args.target]
        scanner = PortScanner(port_cfg)
        all_events.extend(scanner.run())

    if args.all or args.process:
        print("[*] Running Process Scanner...")
        proc_cfg = config.get("process_scanner", {})
        scanner = ProcessScanner(proc_cfg)
        all_events.extend(scanner.run())

    if args.all or args.log:
        print("[*] Running Log Watcher...")
        log_cfg = config.get("log_watcher", {})
        if isinstance(args.log, str) and args.log != True:
            log_cfg["log_file"] = args.log
        scanner = LogWatcher(log_cfg)
        all_events.extend(scanner.run())

    if all_events:
        ingest_events(all_events)
    else:
        print("[*] No events generated.")

if __name__ == "__main__":
    main()
