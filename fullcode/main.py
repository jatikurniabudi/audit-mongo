import subprocess
from pymongo import MongoClient
from pymongo.errors import OperationFailure
import yaml
from getpass import getpass
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
    print(f"    Recommendation: {recommendation}")


class MongoDBSession:
    def __init__(self):
        self.usernname = None
        self.password = None
        self.client = None
    
    def login(self):
        self.username = input("Enter MongoDB username: ")
        self.password = getpass("Enter password: ")
        uri = f"mongodb://{self.username}:{self.password}@localhost:27017"
        self.client = MongoClient(uri, serverSelectionTimeoutMS=3000)

    def get_client(self):
        return self.client
    def get_crefentials(self):
        return self.username, self.password


def check_1_1(required_major=7):
    try:
        output = subprocess.check_output(['mongod', '--version']).decode()
        version_line = output.splitlines()[0]  # Example: "db version v7.0.5"
        version = version_line.split()[-1].lstrip('v')  # Remove '

        major_version = int(version.split('.')[0])
        if major_version >= required_major:
            print_result(
                "1.1 Ensure the appropriate MongoDB software version/patches are installed",
                True,
                f"MongoDB version is {version}, which meets the minimum required version {required_major}.",
                "No action needed. Ensure you keep the patch version up to date.")
        else:
            print_result(
                "1.1 Ensure the appropriate MongoDB software version/patches are installed",
                False,
                f"MongoDB version is {version}, which is below the required major version {required_major}.",
                f"Upgrade MongoDB to version {required_major}.x or later.")

    except Exception as e:
        print_result(
            "1.1 Ensure the appropriate MongoDB software version/patches are installed",
            False,
            f"Failed to determine MongoDB version: {str(e)}",
            "Ensure MongoDB is installed and 'mongod' command is available in PATH."
        )

def check_2_1(config):
    authentication_enabled = config.get("security", {}).get("authorization") == "enabled"
    print_result(
        "2.1 Ensure Authentication is Configured",
        authentication_enabled,
        "authorization is enabled" if authentication_enabled else "authorization is not enabled in mongod.conf",
        "Set security.authorization = enabled in mongod.conf"
    )

def check_2_2(session: MongoDBSession):
    try:
        client = session.get_client()
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

# 3.1 Least privilege for database accounts
def check_3_1(session: MongoDBSession):
    try:
        client = session.get_client()
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
    enabled = config.get("security", {}).get("authorization") == "enabled"
    print_result("3.2 Role-based access control enabled",
                 enabled,
                 "RBAC is enabled" if enabled else "RBAC is not enabled.",
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
def check_3_4(session: MongoDBSession):
    try:
        client = session.get_client()
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
def check_3_5(session: MongoDBSession):
    try:
        client = session.get_client()
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

def check_6_3(session: MongoDBSession):
    try:
        client = (session.get_client())
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


# =========================================# Main execution
if __name__ == '__main__':

    session = MongoDBSession()
    session.login()
    config = load_config()
    # kata_sandi = login_mmongodb()
    check_1_1()
    check_2_1(config)
    check_2_2(session)
    check_2_3(config)
    check_3_1(session)
    check_3_2(config)
    check_3_3()
    check_3_4(session)
    check_3_5(session)
    check_4_1(config)
    check_4_2(config)
    check_4_3(config)
    check_4_4(config)
    check_4_5()
    check_5_1(config)
    check_5_2(config)
    check_5_3(config)
    check_5_4(config)
    check_6_1(config)
    check_6_2()
    check_6_3(session)
    check_7_1(config)
    check_7_2(config)



