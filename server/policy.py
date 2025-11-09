import os
import json
import csv
import stat
from datetime import datetime, timezone
from typing import Tuple, Dict, List, Set, Optional
from enum import IntEnum
from pathlib import Path


base_directory = Path(__file__).parent.parent
data_directory = base_directory / "data"

USER_FILE = data_directory / "users.json"
USER_ROLES_FILE = data_directory / "user_roles.json"
ROLE_PERMS_FILE = data_directory / "role_perms.csv"
ACM_USERS_FILE = data_directory / "acm_users.csv"
AUDIT_LOG_PATH = base_directory / "server" / "audit.jsonl"

class ClearanceLevel(IntEnum):
    UNCLASSIFIED = 0
    CONFIDENTIAL = 1
    SECRET = 2
    TOP_SECRET = 3
    # we can add more/change those

USERS = {}          
USER_ROLES = {}
ROLE_PERMISSIONS = {}
ACM_PERMISSIONS = {}
RESOURCE_LABELS = {}


def load_users():
    """Load users from users.json"""
    global USERS
    try:
        with open(USER_FILE) as f:
            users_list = json.load(f)
            for idx, user in enumerate(users_list):
                username = user["username"]
                
                USERS[username] = {
                    "uid": 1000 + idx,
                    "gid": 1000,
                    "clearance": ClearanceLevel.CONFIDENTIAL,
                    "roles": set(),
                    "salt": user.get("salt"),
                    "password_hash": user.get("password_hash")
                }
    except Exception as e:
        print(f"[POLICY ERROR] Failed to load users: {e}")


def load_user_roles():
    """Load user roles from user_roles.json"""
    global USER_ROLES
    try:
        with open(USER_ROLES_FILE) as f:
            USER_ROLES = json.load(f)
            for username, roles in USER_ROLES.items():
                if username in USERS:
                    USERS[username]["roles"] = set(roles)
    except Exception as e:
        print(f"[POLICY ERROR] Failed to load user roles: {e}")


def load_role_permissions():
    """Load role permissions from role_perms.csv"""
    global ROLE_PERMISSIONS
    try:
        with open(ROLE_PERMS_FILE) as f:
            reader = csv.DictReader(f)
            for row in reader:
                role = row["role"]
                resource = row["resource"]

                if role not in ROLE_PERMISSIONS:
                    ROLE_PERMISSIONS[role] = {}
                if resource not in ROLE_PERMISSIONS[role]:
                    ROLE_PERMISSIONS[role][resource] = set()

                # Add permissions
                if row.get("read") == "read":
                    ROLE_PERMISSIONS[role][resource].add("read")
                if row.get("write") == "write":
                    ROLE_PERMISSIONS[role][resource].add("write")
                if row.get("delete") == "delete":
                    ROLE_PERMISSIONS[role][resource].add("remove")
    except Exception as e:
        print(f"[POLICY ERROR] Failed to load role permissions: {e}")


def load_acm_permissions():
    """Load ACM (Access Control Matrix) permissions from acm_users.csv"""
    global ACM_PERMISSIONS  
    try:
        with open(ACM_USERS_FILE) as f:
            reader = csv.DictReader(f)
            for row in reader:
                user = row["user"]
                resource = row["resource"]

                if user not in ACM_PERMISSIONS:
                    ACM_PERMISSIONS[user] = {}
                if resource not in ACM_PERMISSIONS[user]:
                    ACM_PERMISSIONS[user][resource] = set()

                if row.get("read") == "read":
                    ACM_PERMISSIONS[user][resource].add("read")
                if row.get("write") == "write":
                    ACM_PERMISSIONS[user][resource].add("write")
                if row.get("delete") == "delete":
                    ACM_PERMISSIONS[user][resource].add("remove")
    except Exception as e:
        print(f"[POLICY ERROR] Failed to load ACM permissions: {e}")


def initialize_resource_labels():
    global RESOURCE_LABELS

    RESOURCE_LABELS = {
        "/classified/top_secret": ClearanceLevel.TOP_SECRET,
        "/classified/secret": ClearanceLevel.SECRET,
        "/classified": ClearanceLevel.CONFIDENTIAL,
        "/public": ClearanceLevel.UNCLASSIFIED,
    }


def initialize():
    # we run it only once at startup to load all configs
    load_users()
    load_user_roles()
    load_role_permissions()
    load_acm_permissions()
    initialize_resource_labels()
    print(f"Loaded {len(USERS)} users, {len(ROLE_PERMISSIONS)} roles and {len(ACM_PERMISSIONS)} ACM entries")


def get_resource_label(path: str) -> ClearanceLevel:
    """
    Get MAC classification level for a resource path.
    Returns the highest (most restrictive) matching label.
    If no match, defaults to CONFIDENTIAL (same as user clearance).
    """
    best_match = ClearanceLevel.CONFIDENTIAL  
    best_len = 0

    for pattern, level in RESOURCE_LABELS.items():
        if path.startswith(pattern):
            if len(pattern) > best_len:
                best_match = level
                best_len = len(pattern)

    return best_match


def normalize_operation(operation: str) -> str:
    op_map = {
        "realpath": "stat",

        "stat": "read",
        "lstat": "read",
        "fstat": "read",
        "list": "read",
        "opendir": "read",
        "readdir": "read",
        
        "create": "write",
        "mkdir": "write",
        
        "remove": "write",
    }
    return op_map.get(operation.lower(), operation.lower())


def get_file_mode(full_path: str) -> Optional[int]:
    # mode is an integer representing file mode bits 
    try:
        st = os.stat(full_path)
        return st.st_mode
    except (FileNotFoundError, OSError):
        return None


def get_file_owner(full_path: str) -> Tuple[Optional[int], Optional[int]]:
    # UID is the user ID of the file owner
    # GID is the group ID of the file owner

    try:
        st = os.stat(full_path)
        return st.st_uid, st.st_gid
    except (FileNotFoundError, OSError):
        return None, None # file does not exist


def check_dac(user: str, operation: str, full_path: str) -> Tuple[bool, str]:

    if user not in USERS:
        return False, "DAC: unknown user"

    user_info = USERS[user]
    uid = user_info["uid"]
    gid = user_info["gid"]
    
    op = normalize_operation(operation) # map operation to read/write to decrease complexity (some ops are similar -> smaller ACM matrix)

    mode = get_file_mode(full_path)
    if mode is None:
        # For create operations on non-existent files, check parent directory
        if op in ("write", "remove"):
            parent_path = os.path.dirname(full_path)
            if not parent_path or parent_path == full_path:
                return False, "DAC: invalid path"
            mode = get_file_mode(parent_path)
            if mode is None:
                return True, "DAC: parent does not exist, allowing create"
            file_uid, file_gid = get_file_owner(parent_path)
        else:
            # File doesn't exist and we're trying to read
            return True, "DAC: file does not exist"
    else:
        file_uid, file_gid = get_file_owner(full_path)

    if file_uid is None:
        return True, "DAC: cannot determine ownership"

    # Map operation to required permission
    if op == "read":
        required_perm = stat.S_IRUSR
        shift_group = stat.S_IRGRP
        shift_other = stat.S_IROTH
    elif op in ("write", "remove"):
        required_perm = stat.S_IWUSR
        shift_group = stat.S_IWGRP
        shift_other = stat.S_IWOTH
    else:
        return False, f"DAC: unknown operation {operation}"

    # Check owner
    if uid == file_uid:
        if mode & required_perm:
            return True, "DAC: owner access granted"
        return False, "DAC: owner access denied"

    # Check group
    if gid == file_gid:
        if mode & shift_group:
            return True, "DAC: group access granted"
        return False, "DAC: group access denied"

    # Check other
    if mode & shift_other:
        return True, "DAC: other access granted"

    return False, "DAC: access denied"

def check_mac(user: str, operation: str, path: str) -> Tuple[bool, str]:

    if user not in USERS:
        return False, "MAC: unknown user"

    user_clearance = USERS[user]["clearance"]
    resource_label = get_resource_label(path)

    op = normalize_operation(operation)

    if op == "read":
        # No read up: user must have sufficient clearance
        if user_clearance >= resource_label:
            return True, f"MAC: read allowed (clearance {user_clearance.name} >= label {resource_label.name})"
        return False, f"MAC: no read up violation (clearance {user_clearance.name} < label {resource_label.name})"

    elif op in ("write", "remove"):
        # No write down: user cannot write to less classified resources
        if user_clearance <= resource_label:
            return True, f"MAC: write allowed (clearance {user_clearance.name} <= label {resource_label.name})"
        return False, f"MAC: no write down violation (clearance {user_clearance.name} > label {resource_label.name})"

    return False, f"MAC: unknown operation {operation}"


def check_rbac(user: str, operation: str, path: str) -> Tuple[bool, str]:
  
    if user not in USERS:
        return False, "RBAC: unknown user"

    filename = os.path.basename(path)
    op = normalize_operation(operation)

    # 1. Check ACM permissions (user-specific)
    if user in ACM_PERMISSIONS:
        if filename in ACM_PERMISSIONS[user]:
            if op in ACM_PERMISSIONS[user][filename]:
                return True, f"RBAC: allowed by ACM for user '{user}' on '{filename}'"
            else:
                return False, f"RBAC: denied by ACM for user '{user}' on '{filename}' (operation '{op}' not granted)"

    # 2. Check role permissions (union of all roles)
    user_roles = USERS[user].get("roles", set())
    for role in user_roles:
        if role not in ROLE_PERMISSIONS:
            continue

        if filename in ROLE_PERMISSIONS[role]:
            if op in ROLE_PERMISSIONS[role][filename]:
                return True, f"RBAC: allowed by role '{role}' on '{filename}'"

    return False, f"RBAC: no matching permission for '{filename}'"


def audit_log(user: str, operation: str, path: str, allowed: bool, reason: str):
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user,
        "operation": operation,
        "path": path,
        "allowed": allowed,
        "reason": reason
    }

    try:
        os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[AUDIT ERROR] Failed to write audit log: {e}", flush=True)


def authorize(user: str, operation: str, full_path: str) -> Tuple[bool, str]:

    # Check DAC
    dac_allowed, dac_reason = check_dac(user, operation, full_path)
    if not dac_allowed:
        audit_log(user, operation, full_path, False, dac_reason)
        return False, dac_reason

    # Check MAC 
    mac_allowed, mac_reason = check_mac(user, operation, full_path)
    if not mac_allowed:
        audit_log(user, operation, full_path, False, mac_reason)
        return False, mac_reason

    # Check RBAC
    rbac_allowed, rbac_reason = check_rbac(user, operation, full_path)
    if not rbac_allowed:
        audit_log(user, operation, full_path, False, rbac_reason)
        return False, rbac_reason

    # All checks passed
    combined_reason = f"Access granted: {dac_reason}; {mac_reason}; {rbac_reason}"
    audit_log(user, operation, full_path, True, combined_reason)
    return True, combined_reason


initialize()
if __name__ == "__main__":
    print(f"Users: {list(USERS.keys())}")
    print(f"Roles: {list(ROLE_PERMISSIONS.keys())}")
    print(f"ACM Users: {list(ACM_PERMISSIONS.keys())}")
    print()

    # Test case
    test_user = "alice"
    test_op = "read"
    test_path = "/tmp/model.pkl"

    allowed, reason = authorize(test_user, test_op, test_path)
    print(f"Test: {test_user} -> {test_op} on {test_path}")
    print(f"Result: {'ALLOWED' if allowed else 'DENIED'}")
    print(f"Reason: {reason}")
