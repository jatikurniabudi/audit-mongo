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

# 3.1 Least privilege for database accounts
def check_3_1():
    try:
        client = MongoClient("mongodb://localhost:27017")
        users = client["admin"].command("usersInfo")['users']
        flagged = []
        for user in users:
            for role in user.get("roles", []):
                if role["role"] in ["dbOwner", "userAdmin", "readWriteAnyDatabase", "root"]:
                    flagged.append((user["user"], role["role"]))
        if flagged:
            reason = f"Users with potentially excessive roles: {flagged}"
            recommendation = "Review and assign minimal privileges per user role."
            print_result("3.1 Least privilege for database accounts", False, reason, recommendation)
        else:
            print_result("3.1 Least privilege for database accounts", True, "No overprivileged roles found.", "No action needed.")
    except Exception as e:
        print_result("3.1 Least privilege for database accounts", False, str(e), "Ensure MongoDB is running and user has access.")

# 3.2 RBAC is enabled
def check_3_2(config):
    rbac_enabled = config.get("security", {}).get("authorization") == "enabled"
    print_result("3.2 Role-based access control enabled",
                 rbac_enabled,
                 "RBAC is enabled" if rbac_enabled else "RBAC is not enabled.",
                 "Set 'security.authorization: enabled' in mongod.conf.")

# 3.3 mongod runs as non-root user
def check_3_3():
    try:
        output = subprocess.check_output(["ps", "-eo", "user,comm"]).decode()
        for line in output.splitlines():
            if "mongod" in line:
                user = line.split()[0]
                if user == "root":
                    print_result("3.3 mongod runs as non-root", False, "mongod is running as root.", "Run mongod under a dedicated, non-root user.")
                    return
                else:
                    print_result("3.3 mongod runs as non-root", True, f"mongod is running as {user}.", "No action needed.")
                    return
        print_result("3.3 mongod runs as non-root", False, "mongod process not found.", "Ensure mongod is running.")
    except Exception as e:
        print_result("3.3 mongod runs as non-root", False, str(e), "Error checking process list.")

# 3.4 Ensure each role grants only necessary privileges
def check_3_4():
    try:
        client = MongoClient("mongodb://localhost:27017")
        roles = client["admin"].command("rolesInfo", showPrivileges=True)["roles"]
        risky_roles = []
        for role in roles:
            for priv in role.get("privileges", []):
                if priv["resource"].get("db") == "" or priv["actions"] == ["*"]:
                    risky_roles.append(role["role"])
        if risky_roles:
            print_result("3.4 Each role grants only necessary privileges", False,
                         f"Risky roles: {risky_roles}",
                         "Review custom roles and restrict wildcard privileges.")
        else:
            print_result("3.4 Each role grants only necessary privileges", True,
                         "No overly permissive roles found.",
                         "No action needed.")
    except Exception as e:
        print_result("3.4 Each role grants only necessary privileges", False, str(e), "Ensure connection is allowed and user has access.")

# 3.5 Review Superuser/Admin Roles
def check_3_5():
    try:
        client = MongoClient("mongodb://localhost:27017")
        users = client["admin"].command("usersInfo")["users"]
        superusers = []
        for user in users:
            for role in user.get("roles", []):
                if role["role"] in ["root", "userAdminAnyDatabase", "dbAdminAnyDatabase"]:
                    superusers.append(user["user"])
        if superusers:
            print_result("3.5 Review Superuser/Admin Roles", False,
                         f"Users with superuser roles: {superusers}",
                         "Limit number of users with superuser roles.")
        else:
            print_result("3.5 Review Superuser/Admin Roles", True,
                         "No users with root/admin roles found.",
                         "No action needed.")
    except Exception as e:
        print_result("3.5 Review Superuser/Admin Roles", False, str(e), "Ensure access to MongoDB admin DB.")

if __name__ == "__main__":
    config = load_config()
    check_3_1()
    check_3_2(config)
    check_3_3()
    check_3_4()
    check_3_5()
