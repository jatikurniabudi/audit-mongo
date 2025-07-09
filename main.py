import os
import yaml
import subprocess
from pymongo import MongoClient
from pymongo.errors import OperationFailure

CONFIG_FILE = "/etc/mongod.conf"


def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        return {}


def print_result(section, status, reason, recommendation):
    print(f"[{'OK' if status else 'FAIL'}] {section}")
    print(f"    Reason: {reason}")
    print(f"    Recommendation: {recommendation}\n")


# 1.1 Ensure the appropriate MongoDB software version/patches are installed
def check_1_1():
    try:
        version_output = subprocess.check_output(['mongod', '--version']).decode()
        version_line = version_output.splitlines()[0]
        version = version_line.split(' ')[-1]
        major_version = int(version.split('.')[0])
        if major_version >= 7:
            print_result("1.1 Appropriate MongoDB version installed", True,
                         f"MongoDB version is {version}",
                         "Ensure MongoDB version is 7.x or later with latest patches.")
        else:
            print_result("1.1 Appropriate MongoDB version installed", False,
                         f"MongoDB version is {version}",
                         "Upgrade to MongoDB 7.x or later.")
    except Exception as e:
        print_result("1.1 Appropriate MongoDB version installed", False,
                     str(e),
                     "Check MongoDB installation and version command.")


# 2.1 Ensure 'bindIp' is configured correctly
def check_2_1(config):
    try:
        bind_ip = config.get('net', {}).get('bindIp', '')
        if bind_ip == "127.0.0.1" or bind_ip.startswith("127."):
            print_result("2.1 bindIp is restricted", True,
                         f"bindIp is set to {bind_ip}",
                         "No action needed.")
        else:
            print_result("2.1 bindIp is restricted", False,
                         f"bindIp is set to {bind_ip}",
                         "Set bindIp to '127.0.0.1' or specific trusted IPs only.")
    except Exception as e:
        print_result("2.1 bindIp is restricted", False,
                     str(e),
                     "Ensure mongod.conf has proper 'net.bindIp' setting.")


# 3.1 Ensure authentication is enabled
def check_3_1(config):
    try:
        auth = config.get('security', {}).get('authorization', '').lower()
        if auth == 'enabled':
            print_result("3.1 Authentication enabled", True,
                         "authorization is set to 'enabled'",
                         "No action needed.")
        else:
            print_result("3.1 Authentication enabled", False,
                         f"authorization is set to '{auth}'",
                         "Set 'authorization: enabled' under security in mongod.conf")
    except Exception as e:
        print_result("3.1 Authentication enabled", False,
                     str(e),
                     "Ensure mongod.conf has 'security.authorization' set correctly.")


# 3.2 Ensure unauthenticated access is not allowed
def check_3_2():
    try:
        client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=3000)
        client.server_info()
        print_result("3.2 Unauthenticated access blocked", False,
                     "MongoDB can be accessed without authentication.",
                     "Enable authentication and restart MongoDB service.")
    except OperationFailure:
        print_result("3.2 Unauthenticated access blocked", True,
                     "Access is restricted without authentication.",
                     "No action needed.")
    except Exception as e:
        print_result("3.2 Unauthenticated access blocked", False,
                     str(e),
                     "Ensure MongoDB is running and accessible locally.")


def run_all():
    config = load_config()
    check_1_1()
    check_2_1(config)
    check_3_1(config)
    check_3_2()


if __name__ == '__main__':
    run_all()
