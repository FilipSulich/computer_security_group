import json, csv, sys
from pathlib import Path
from datetime import datetime

# Global operation mapping
# Maps SFTP operations to permission categories
OPERATION_MAP = {
    'realpath': 'read',
    'stat': 'read',
    'list': 'read',
    'read': 'read',
    'write': 'write',
    'mkdir': 'write',
    'remove': 'delete'
}

OPERATION_MAP_DAC = {
    'realpath': 'read',
    'stat': 'stat',
    'list': 'list',
    'read': 'read',
    'write': 'write',
    'mkdir': 'write',
    'remove': 'delete'
}

class AccessControl:
    def __init__(self):
        # Get the data directory relative to this script
        self.data_dir = Path(__file__).parent.parent / "data"
        self.load_policies()
        self.audit_file = open(self.data_dir / "audit_policy.jsonl", "a")

    def load_policies(self):
        """Load all policy files with error handling"""

        # Load user_roles.json
        try:
            with open(self.data_dir / "user_roles.json") as f:
                self.user_roles = json.load(f)
            print("[POLICY] Loaded user_roles.json")
        except Exception as e:
            print(f"[POLICY] FATAL: Failed to load user_roles.json: {e}", file=sys.stderr)
            sys.exit(1)

        # Load user_groups.json
        try:
            with open(self.data_dir / "user_groups.json") as f:
                self.user_groups = json.load(f)
            print("[POLICY] Loaded user_groups.json")
        except Exception as e:
            print(f"[POLICY] FATAL: Failed to load user_groups.json: {e}", file=sys.stderr)
            sys.exit(1)

        # Load role_perms.csv
        try:
            self.role_perms = {}
            with open(self.data_dir / "role_perms.csv") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    role = row['role']
                    resource = row['resource']

                    if role not in self.role_perms:
                        self.role_perms[role] = {}

                    if resource not in self.role_perms[role]:
                        self.role_perms[role][resource] = set()

                    # Store only the operations allowed
                    if row.get('read') == 'yes':
                        self.role_perms[role][resource].add('read')
                    if row.get('write') == 'yes':
                        self.role_perms[role][resource].add('write')
                    if row.get('delete') == 'yes':
                        self.role_perms[role][resource].add('delete')
            print("[POLICY] Loaded role_perms.csv")
        except Exception as e:
            print(f"[POLICY] FATAL: Failed to load role_perms.csv: {e}", file=sys.stderr)
            sys.exit(1)

        # Load mac_labels.json
        try:
            with open(self.data_dir / "mac_labels.json") as f:
                mac_data = json.load(f)
                self.user_clearances = mac_data['users']
                self.path_labels = mac_data['paths']
                self.mac_levels = mac_data['levels']
            print("[POLICY] Loaded mac_labels.json")
        except Exception as e:
            print(f"[POLICY] FATAL: Failed to load mac_labels.json: {e}", file=sys.stderr)
            sys.exit(1)

        # Load dac_owners.csv
        try:
            self.dac_rules = {}
            with open(self.data_dir / "dac_owners.csv") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    path_prefix = row['path']
                    owner = row['owner']
                    group = row['group']
                    mode = row['mode']

                    # Convert mode from octal string to integer
                    mode_int = int(mode, 8) if mode.startswith('0o') or mode.startswith('0') else int(mode, 8)

                    self.dac_rules[path_prefix] = {
                        'owner': owner,
                        'group': group,
                        'mode': mode_int
                    }
            print("[POLICY] Loaded dac_owners.csv")
        except Exception as e:
            print(f"[POLICY] FATAL: Failed to load dac_owners.csv: {e}", file=sys.stderr)
            sys.exit(1)

        print("[POLICY] All policy files loaded successfully")
    
    def authorize(self, user, operation, path):
        """
        Unified authorization gate
        Returns: (allowed: bool, reason: str)
        """
        # DAC check
        dac_allowed, dac_reason = self.check_dac(user, operation, path)
        
        # MAC check
        mac_allowed, mac_reason = self.check_mac(user, operation, path)
        
        # RBAC check
        rbac_allowed, rbac_reason = self.check_rbac(user, operation, path)
        
        # Composition: ALL must allow (DAC ∧ MAC ∧ RBAC)
        allowed = dac_allowed and mac_allowed and rbac_allowed
        
        if not allowed:
            reason = f"DAC: {dac_reason} | MAC: {mac_reason} | RBAC: {rbac_reason}"
        else:
            reason = "Allowed by all policies"
        
        # Audit
        record = self.audit(user, operation, path, allowed, reason)
        
        return allowed, record
    
    def check_dac(self, user, operation, path):
        """Discretionary Access Control using dac_owners.csv with owner/group/other"""

        # Find longest matching path prefix in DAC rules
        best_match = None
        best_match_len = 0

        for path_prefix, rule in self.dac_rules.items():
            if path.startswith(path_prefix):
                if len(path_prefix) > best_match_len:
                    best_match = path_prefix
                    best_match_len = len(path_prefix)

        # If no match found, deny by default
        if not best_match:
            return False, "DENY, no matching rule for path"

        rule = self.dac_rules[best_match]
        owner = rule['owner']
        group = rule['group']
        mode = rule['mode']

        # Get user's groups (empty list if user not found)
        user_groups = self.user_groups.get(user, [])

        # Normalize operation using dac map
        normalized_op = OPERATION_MAP_DAC.get(operation, operation)

        # Check permissions in order: owner -> group -> other
        if user == owner:
            # User is owner - check owner bits (rwx-------)
            if normalized_op == 'read':
                if mode & 0o400:  # Owner read bit
                    return True, f"ALLOW"
            elif normalized_op in ['write', 'delete']:
                if mode & 0o200:  # Owner write bit
                    return True, f"ALLOW"
            elif normalized_op == 'stat':
                if mode & 0o100:  # Owner execute bit
                    return True, f"ALLOW"
            elif normalized_op == 'list':
                if mode & 0o100 and mode & 0o400:  # Owner list bit (requires both read and execute)
                    return True, f"ALLOW"
            # Owner permissions don't allow this operation
            return False, f"DENY, owner lacks permission on {best_match} (mode={oct(mode)})"

        elif group in user_groups:
            # User is in the file's group - check group bits (---rwx---)
            if normalized_op == 'read':
                if mode & 0o040:  # Group read bit
                    return True, f"ALLOW"
            elif normalized_op in ['write', 'delete']:
                if mode & 0o020:  # Group write bit
                    return True, f"ALLOW"
            elif normalized_op == 'stat':
                if mode & 0o010:  # Group execute bit
                    return True, f"ALLOW"
            elif normalized_op == 'list':
                if mode & 0o010 and mode & 0o040:  # Group list bit (requires both read and execute)
                    return True, f"ALLOW"

            # Group permissions don't allow this operation
            return False, f"DENY, group '{group}' lacks permission on {best_match} (mode={oct(mode)})"

        else:
            # User is neither owner nor in group - check other bits (------rwx)
            if normalized_op == 'read':
                if mode & 0o004:  # Other read bit
                    return True, f"ALLOW"
            elif normalized_op in ['write', 'delete']:
                if mode & 0o002:  # Other write bit
                    return True, f"ALLOW"
            elif normalized_op == 'stat':
                if mode & 0o001:  # Other execute bit
                    return True, f"ALLOW"
            elif normalized_op == 'list':
                if mode & 0o001 and mode & 0o004:  # Other list bit (requires both read and execute)
                    return True, f"ALLOW"
            # Other permissions don't allow this operation
            return False, f"DENY, other lacks permission on {best_match} (mode={oct(mode)})"
    
    def check_mac(self, user, operation, path):
        """Mandatory Access Control"""
        user_clearance = self.user_clearances.get(user, "public")

        # Find path label (match longest prefix for most specific match)
        path_label = "confidential"
        best_match_len = 0

        for prefix, label in self.path_labels.items():
            if path.startswith(prefix):
                if len(prefix) > best_match_len:
                    path_label = label
                    best_match_len = len(prefix)

        user_level = self.mac_levels.index(user_clearance)
        resource_level = self.mac_levels.index(path_label)

        # Normalize operation using global map
        normalized_op = OPERATION_MAP.get(operation, operation)

        # No read up
        if normalized_op == 'read':
            if user_level < resource_level:
                return False, f"DENY, no read up ({user_clearance} < {path_label})"

        # No write down
        if normalized_op in ['write', 'delete']:
            if user_level != resource_level:
                return False, f"DENY, no write down ({user_clearance} != {path_label})"

        return True, f"ALLOW"
    
    def check_rbac(self, user, operation, path):
        """Role-Based Access Control"""
        roles = self.user_roles.get(user, [])

        # Normalize operation using global map
        normalized_op = OPERATION_MAP.get(operation, operation)

        # Find longest matching resource across all roles (most specific wins)
        best_match = None
        best_match_len = 0
        best_role = None

        for role in roles:
            # Get dict of resources for this role
            role_resources = self.role_perms.get(role, {})

            # Check each resource the role has access to
            for resource, allowed_ops in role_resources.items():
                # Check if path matches resource (prefix match)
                if path.startswith(resource):
                    # Keep track of longest match
                    if len(resource) > best_match_len:
                        best_match = resource
                        best_match_len = len(resource)
                        best_role = role
                        # Store the allowed operations for this match
                        best_allowed_ops = allowed_ops

        # Check if we found a match and if the operation is allowed
        if best_match and normalized_op in best_allowed_ops:
            return True, f"ALLOW"

        return False, "DENY, no matching role permission"
    
    def audit(self, user, operation, path, allowed, reason):
        """Write audit log"""
        record = {
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "operation": operation,
            "path": path,
            "allowed": allowed,
            "reason": reason
        }
        self.audit_file.write(json.dumps(record) + "\n")
        self.audit_file.flush()
        return record