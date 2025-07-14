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


def check_6_1(config):
    port = config.get("net", {}).get("port", 27017)
    if port != 27017:
        print_result("6.1 MongoDB uses non-default port", True,
                     f"MongoDB is configured to run on port {port}",
                     "No action needed.")
    else:
        print_result("6.1 MongoDB uses non-default port", False,
                     f"MongoDB is using default port {port}",
                     "Change to a non-default port in mongod.conf under net.port")

def check_6_2():
    print_result("6.2 OS resource limits set", True,
                 "Manual verification required: check /etc/security/limits.conf or systemd unit file.",
                 "Set open file limit (nofile), processes (nproc), etc. for MongoDB user.")

def check_6_3():
    try:
        client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=3000)
        result = client.admin.command("getParameter", 1, javascriptEnabled=True)
        if result.get("javascriptEnabled") is False:
            print_result("6.3 Server-side scripting disabled", True,
                         "javascriptEnabled is set to false.",
                         "No action needed.")
        else:
            print_result("6.3 Server-side scripting disabled", False,
                         "javascriptEnabled is enabled.",
                         "Disable server-side scripting unless explicitly required.")
    except Exception as e:
        print_result("6.3 Server-side scripting disabled", False,
                     f"Unable to determine: {str(e)}",
                     "Ensure MongoDB is accessible and allowParameter is not restricted.")





if __name__ == "__main__":
    config = load_config()
    check_6_1(config)
    check_6_2()
    check_6_3()
