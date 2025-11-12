# Authorization Policy Documentation

## Overview

Our SFTP server uses three security layers: DAC, MAC, and RBAC. All three must approve access for it to be granted.

**Default policy: DENY unless all three allow.**

---

## Operations

We support these SFTP commands:
- **Read operations:** `realpath`, `stat`, `list`, `read`
- **Write operations:** `write`, `mkdir`
- **Delete operations:** `remove` (`remove` classified as Write for DAC and MAC)

## Path 
For any path the authorization method looks for longest match in each system.

### Example:
```csv
user,resource,read,write,delete
alice,/data/secure/,yes,no,no
alice,/data/,yes,yes,no
```
**example**:
```
user: Alice, path: /data/secure/file.txt, operation: write 
=> longest path match = /data/secure/
=> Access DENIED
```

```
user: Alice, path: /data/file.txt, operation: write 
=> longest path match = /data/ 
=> Access GRANTED
```

---

## DAC (Discretionary Access Control)

### How it works
Similar to Unix file permissions - each file has an owner, group, and permissions.

### Configuration
**File:** `data/dac_owners.csv`
```csv
path,owner,group,mode
/reports/,alice,interns,0o640
```

**File:** `data/user_groups.json`
```json
{
  "alice": ["interns"]
}
```

### Permission bits
```
Mode 0o640 = rw-r-----
             │││││││││
             ││││││││└─ Other write  (0o002)
             │││││││└── Other read   (0o004)
             ││││││└─── Group write  (0o020)
             │││││└──── Group read   (0o040)
             ││││└───── Owner write  (0o200)
             │││└────── Owner read   (0o400)
```

Read operations need read bit (4), write/delete need write bit (2).

### Permission check order
1. If you're the owner → check owner bits
2. Else if you're in the file's group → check group bits
3. Else → check other bits

### Examples

**Owner can read and write:**
```
Path: /reports/Q1.pdf
Owner: alice
Group: interns
Mode: 0o640 (rw-r-----)

User: alice, Operation: read
ALLOWED - alice is owner, has read bit (0o400)

User: alice, Operation: write
ALLOWED - alice is owner, has write bit (0o200)
```

**Group can read but not write:**
```
Path: /reports/Q1.pdf
Owner: alice
Group: interns
Mode: 0o640 (rw-r-----)

User: bob (in interns group), Operation: read
ALLOWED - group has read bit (0o040)

User: bob (in interns group), Operation: write
DENIED - group lacks write bit (0o020 not set)
```

**Other has no access:**
```
Path: /reports/Q1.pdf
Owner: alice
Group: interns
Mode: 0o640 (rw-r-----)

User: charlie (not in interns group), Operation: read
DENIED - other has no read bit (0o004 not set)
```

---

## MAC (Mandatory Access Control)

### How it works
Users have clearance levels, files have classification labels. File with no specified classification assumed to be confidential. User with no clearence assumed to be public, i.e. no information about file or user -> be as secure as possible.

**Rules:**
- **No read up:** Can't read files above your clearance
- **No write down:** Can't write to files below your clearance

### Configuration
**File:** `data/mac_labels.json`
```json
{
  "users": {
    "alice": "internal"
  },
  "paths": {
    "/confidential": "confidential",
    "/internal": "internal",
    "/public": "public"
  },
  "levels": ["public", "internal", "confidential"]
}
```

### Examples

**Read up blocked:**
```
User: alice (clearance: internal)
File: /confidential/data.txt (label: confidential)
Operation: read
DENIED - confidential < top_secret (no read up)
```

**Write down blocked:**
```
User: alice (clearance: internal)
File: /public/readme.txt (label: public)
Operation: write
DENIED - secret > public (no write down)
```

**Same level allowed:**
```
User: alice (clearance: confidential)
File: /confidential/budget.xlsx (label: confidential)
Operation: read
ALLOWED - confidential = confidential
```

---

## RBAC (Role-Based Access Control)

### How it works
Users have roles, roles have permissions. If ANY role grants access, you're allowed (union of permissions). No user-specific deny/allow implementation.

### Configuration
**File:** `data/user_roles.json`
```json
{
  "alice": ["intern"]
}
```

**File:** `data/role_perms.csv`
```csv
role,resource,read,write,delete
intern,/data/reports,yes,no,no
admin,/data/secret,yes,yes,no
```

### Examples

**Role grants permission:**
```
User: Alice, Roles: [intern]
File: /data/reports/Q1.pdf
Operation: read
ALLOWED - analyst role has read on /data/reports
```

**Role denies:**
```
User: Alice, Roles: [intern]
File: /data/secret/budget.pdf
Operation: read
DENIED - intern role only has no rights on /data/secret/
```

**Multiple roles (union):**
```
User: alice, Roles: [analyst, admin]
File: /data/secret/budget.pdf
Operation: write
ALLOWED - admin role grants write (even though intern doesn't)
```

---

## Final Decision

**Formula:** `ALLOW = DAC_allow AND MAC_allow AND RBAC_allow`

All three must say yes. If any says no, request is denied.

### Example outcomes

| DAC | MAC | RBAC | Result |
|-----|-----|------|--------|
| ✓ | ✓ | ✓ | ✓ **ALLOW** |
| ✗ | ✓ | ✓ | ✗ **DENY** (DAC blocked) |
| ✓ | ✗ | ✓ | ✗ **DENY** (MAC blocked) |
| ✓ | ✓ | ✗ | ✗ **DENY** (RBAC blocked) |

### Combined example

```
User: alice
Groups: [interns]
Roles: [intern]
Clearance: confidential

File: /data/reports/Q1.pdf
Owner: alice
Group: interns
Mode: 0o640
Label: confidential

somewhere in RBAC:
intern,/data/reports/,yes,yes,no

Operation: read

DAC:  alice is owner, has read bit → ✓ ALLOW
MAC:  confidential = confidential → ✓ ALLOW
RBAC: intern role has read → ✓ ALLOW

Final: ✓ ALLOW
```

---

## Audit Logging

Every decision gets logged to `data/audit_policy.jsonl`:

```json
{
  "timestamp": "2025-01-15T14:23:45.123456",
  "user": "alice",
  "operation": "read",
  "path": "/data/reports/Q1.pdf",
  "allowed": true,
  "reason": "Allowed by all policies"
}
```

### Example denied access
```json
{
  "timestamp": "2025-01-15T14:24:12.789012",
  "user": "bob",
  "operation": "write",
  "path": "/public/readme.txt",
  "allowed": false,
  "reason": "DAC: allowed, MAC: no write down (confidential > public), RBAC: allowed"
}
```

This shows Bob failed because of MAC (write down violation) even though DAC and RBAC allowed it.

---

## Summary

- **Operations** = `realpath`, `stat`, `list`, `read`, `write`, `mkdir`, `remove`
- **Path** = Longest prefix match, child files inherit parents permits
- **DAC** = Unix file permissions (owner/group/other)
- **MAC** = Clearance levels (no read up, no write down)
- **RBAC** = Role-based permissions (union of all roles)
- **Decision** = All three must approve
- **Logging** = Everything logged to audit_policy.jsonl
