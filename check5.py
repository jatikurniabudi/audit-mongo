import subprocess
from pymongo import MongoClient
from pymongo.errors import OperationFailure
import os

CONFIG_FILE = "/etc/mongod.conf"

def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f)
    except:
        return {}

def print_result(section, status, reason, recommendation):
    print(f"[{'OK' if status else 'FAIL'}] {section}")
    print(f"    Reason        : {reason}")
    print(f"    Recommendation: {recommendation}\n")


import os

def check_5_1(config):
    dest = config.get("auditLog", {}).get("destination")
    if dest:
        print_result("5.1 Audit system activity", True,
                     f"auditLog.destination is set to '{dest}'",
                     "No action needed.")
    else:
        print_result("5.1 Audit system activity", False,
                     "auditLog.destination not set",
                     "Enable audit logging by configuring 'auditLog.destination' in mongod.conf")

def check_5_2(config):
    filters = config.get("auditLog", {}).get("filter")
    if filters:
        print_result("5.2 Audit filters configured", True,
                     f"Audit filters present: {filters[:80]}...",
                     "Review audit filters to ensure appropriate coverage.")
    else:
        print_result("5.2 Audit filters configured", False,
                     "No audit filters found.",
                     "Set 'auditLog.filter' in mongod.conf to define what should be audited.")

def check_5_3(config):
    format_val = config.get("auditLog", {}).get("format", "unknown")
    verbosity = config.get("systemLog", {}).get("verbosity", "default")
    if format_val.lower() in ["bson", "json"] and verbosity in [0, 1, 2, 3, 4, 5]:
        print_result("5.3 Logging captures detailed info", True,
                     f"auditLog.format is '{format_val}', verbosity is {verbosity}",
                     "No action needed.")
    else:
        print_result("5.3 Logging captures detailed info", False,
                     f"format='{format_val}', verbosity='{verbosity}'",
                     "Use 'bson' or 'json' for auditLog.format and increase verbosity if needed.")

def check_5_4(config):
    path = config.get("auditLog", {}).get("path")
    if path and os.path.exists(path):
        try:
            with open(path, "a") as f:
                f.write("")  # test append
            print_result("5.4 Log appending works", True,
                         f"Audit log at {path} is writable and appendable.",
                         "No action needed.")
        except Exception as e:
            print_result("5.4 Log appending works", False,
                         f"Failed to append to audit log: {str(e)}",
                         "Ensure MongoDB has permission to append to audit log.")
    else:
        print_result("5.4 Log appending works", False,
                     "Audit log path is missing or invalid.",
                     "Check 'auditLog.path' in mongod.conf and ensure it exists.")




if __name__ == "__main__":
    config = load_config()
    check_5_1(config)
    check_5_2(config)
    check_5_3(config)
    check_5_4(config)
