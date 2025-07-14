from pymongo import MongoClient
from pymongo.errors import OperationFailure
import yaml

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
    print(f"    Recommendation: {recommendation}")

# 2.1 Ensure authentication is configured
def check_2_1(config):
    auth_enabled = config.get("security", {}).get("authorization") == "enabled"
    print_result(
        "2.1 Ensure Authentication is Configured",
        auth_enabled,
        "authorization is enabled" if auth_enabled else "authorization is not enabled in mongod.conf",
        "Set security.authorization = enabled in mongod.conf"
    )

# 2.2 Ensure MongoDB does not bypass authentication via localhost exception
def check_2_2():
    try:
        client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=3000)
        users = client["admin"].command("usersInfo")
        user_count = len(users.get("users", []))
        if user_count > 0:
            print_result(
                "2.2 Localhost Authentication Bypass Disabled",
                True,
                f"{user_count} user(s) exist in admin database.",
                "No action needed."
            )
        else:
            print_result(
                "2.2 Localhost Authentication Bypass Disabled",
                False,
                "No admin users found — localhost exception may still be active.",
                "Create at least one admin user to disable localhost bypass."
            )
    except Exception as e:
        print_result(
            "2.2 Localhost Authentication Bypass Disabled",
            False,
            f"Failed to connect or query: {str(e)}",
            "Ensure MongoDB is running and accessible."
        )

# 2.3 Ensure authentication is enabled in sharded cluster
def check_2_3(config):
    is_auth = config.get("security", {}).get("authorization") == "enabled"
    cluster_role = config.get("sharding", {}).get("clusterRole")
    if cluster_role:  # Only applies if this is part of sharded cluster
        print_result(
            "2.3 Authentication Enabled in Sharded Cluster",
            is_auth,
            f"Cluster role is {cluster_role}, authorization is {'enabled' if is_auth else 'disabled'}",
            "Ensure all mongos, config servers, and shards have authorization enabled"
        )
    else:
        print_result(
            "2.3 Authentication Enabled in Sharded Cluster",
            True,
            "Not a sharded cluster node",
            "No action needed."
        )

# === Jalankan semua ===
if __name__ == "__main__":
    config = load_config()
    check_2_1(config)
    check_2_2()
    check_2_3(config)
