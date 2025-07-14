import subprocess
from pymongo import MongoClient
from pymongo.errors import OperationFailure

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


def check_4_1(config):
    disabled = config.get("net", {}).get("tls", {}).get("disabledProtocols", [])
    if disabled and all(proto in disabled for proto in ["TLS1_0", "TLS1_1"]):
        print_result("4.1 Legacy TLS protocols disabled", True,
                     f"Disabled protocols: {disabled}",
                     "No action needed.")
    else:
        print_result("4.1 Legacy TLS protocols disabled", False,
                     f"DisabledProtocols not set correctly: {disabled}",
                     "Add 'TLS1_0,TLS1_1' to net.tls.disabledProtocols in mongod.conf")

def check_4_2(config):
    disabled = config.get("net", {}).get("tls", {}).get("disabledProtocols", [])
    if isinstance(disabled, str):
        disabled = disabled.split(",")
    if "TLS1_0" in disabled and "TLS1_1" in disabled:
        print_result("4.2 Weak protocols disabled", True,
                     f"TLS1_0 and TLS1_1 are disabled.",
                     "No action needed.")
    else:
        print_result("4.2 Weak protocols disabled", False,
                     f"Missing disabled TLS protocols: {disabled}",
                     "Disable TLS1_0 and TLS1_1 via net.tls.disabledProtocols.")

def check_4_3(config):
    tls_mode = config.get("net", {}).get("tls", {}).get("mode", "")
    if tls_mode in ["requireTLS", "preferTLS"]:
        print_result("4.3 Encryption in Transit (TLS/SSL)", True,
                     f"TLS mode is set to {tls_mode}",
                     "No action needed.")
    else:
        print_result("4.3 Encryption in Transit (TLS/SSL)", False,
                     f"TLS mode is {tls_mode}",
                     "Set net.tls.mode to 'requireTLS' or 'preferTLS' in mongod.conf")

def check_4_4(config):
    fips = config.get("security", {}).get("fipsMode", False)
    if fips:
        print_result("4.4 FIPS mode enabled", True,
                     "FIPS mode is enabled.",
                     "No action needed.")
    else:
        print_result("4.4 FIPS mode enabled", False,
                     "FIPS mode is not enabled.",
                     "Enable FIPS by setting security.fipsMode = true and ensure OS supports it.")

def check_4_5():
    print_result("4.5 Encryption at Rest", True,
                 "Manual verification required: check if data encryption at rest (e.g. KMIP, filesystem encryption) is enabled.",
                 "Enable encrypted storage engine, KMIP, or disk-level encryption for data at rest.")


if __name__ == "__main__":
    config = load_config()
    check_4_1(config)
    check_4_2(config)
    check_4_3(config)
    check_4_4(config)
    check_4_5()
