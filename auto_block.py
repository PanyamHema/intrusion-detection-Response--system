#!/usr/bin/env python3
import re, subprocess, time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

ALERT_FILE = "/var/log/snort/alert"
BLOCKED = set()

class AlertHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path != ALERT_FILE:
            return
        with open(ALERT_FILE) as f:
            lines = f.readlines()
        for line in lines[-10:]:
            m = re.search(r'->(\d+\.\d+\.\d+\.\d+):(\d+)', line)
            if m:
                ip = m.group(1)
                if ip not in BLOCKED:
                    print(f"[!] Blocking IP {ip}")
                    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
                    BLOCKED.add(ip)

if __name__ == "__main__":
    event_handler = AlertHandler()
    observer = Observer()
    observer.schedule(event_handler, path="/var/log/snort", recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
