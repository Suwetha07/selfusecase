import psutil
import json
import datetime
from pathlib import Path
WHITELIST = [
    {"port": 22, "process": "sshd"},
    {"port": 80, "process": "nginx"},
    {"port": 443, "process": "nginx"},
    {"port": 3306, "process": "mysqld"},
]
REPORT_FILE = "security_report.json"
def get_open_ports():
    results = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
            try:
                pid = conn.pid
                process = psutil.Process(pid) if pid else None
                process_name = process.name() if process else "Unknown"
                user = process.username() if process else "Unknown"

                results.append({
                    "port": conn.laddr.port,
                    "ip": conn.laddr.ip,
                    "pid": pid,
                    "process": process_name,
                    "user": user
                })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    return results
def is_whitelisted(port, process):
    for approved in WHITELIST:
        if approved["port"] == port and approved["process"] in process:
            return True
    return False
def analyze_ports():
    open_ports = get_open_ports()
    suspicious = []
    approved = []
    for entry in open_ports:
        if is_whitelisted(entry["port"], entry["process"]):
            entry["status"] = "approved"
            approved.append(entry)
        else:
            entry["status"] = "suspicious"
            suspicious.append(entry)

    return approved, suspicious

def generate_report():
    approved, suspicious = analyze_ports()

    report = {
        "scan_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "total_open_ports": len(approved) + len(suspicious),
        "approved_services": approved,
        "suspicious_services": suspicious,
        "risk_level": "HIGH" if suspicious else "LOW"
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=4)

    return report

if __name__ == "__main__":
    report = generate_report()
    print("\n=== SECURITY REPORT SUMMARY ===")
    print(f"Scan Time: {report['scan_timestamp']}")
    print(f"Total Open Ports: {report['total_open_ports']}")
    print(f"Suspicious Services: {len(report['suspicious_services'])}")
    print(f"Risk Level: {report['risk_level']}")
    print(f"\nFull report saved to: {Path(REPORT_FILE).absolute()}")
