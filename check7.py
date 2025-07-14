import subprocess
from pymongo import MongoClient
from pymongo.errors import OperationFailure
import os
import stat


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


def check_7_1(config):
    key_path = config.get("security", {}).get("keyFile")
    if key_path and os.path.exists(key_path):
        st = os.stat(key_path)
        mode = oct(st.st_mode & 0o777)
        if mode in ['0o600', '0o400']:
            print_result("7.1 Key file permissions", True,
                         f"Key file '{key_path}' has permission {mode}",
                         "No action needed.")
        else:
            print_result("7.1 Key file permissions", False,
                         f"Key file '{key_path}' has insecure permissions: {mode}",
                         "Set permission to 600 (rw-------) or 400 (r--------).")
    else:
        print_result("7.1 Key file permissions", False,
                     f"Key file not found or not configured.",
                     "Set 'security.keyFile' in mongod.conf and secure the file (chmod 600).")

# 7.2 - DB file permissions
def check_7_2(config):
    db_path = config.get("storage", {}).get("dbPath", "/var/lib/mongo")
    if os.path.exists(db_path):
        st = os.stat(db_path)
        mode = oct(st.st_mode & 0o777)
        if mode in ['0o700', '0o750']:
            print_result("7.2 Database file permissions", True,
                         f"dbPath '{db_path}' has permission {mode}",
                         "No action needed.")
        else:
            print_result("7.2 Database file permissions", False,
                         f"dbPath '{db_path}' has insecure permissions: {mode}",
                         "Restrict dbPath permissions to 700 or 750.")
    else:
        print_result("7.2 Database file permissions", False,
                     f"dbPath '{db_path}' not found.",
                     "Ensure MongoDB data directory exists and is properly secured.")

if __name__ == "__main__":
    config = load_config()
    check_7_1(config)
    check_7_2(config)
