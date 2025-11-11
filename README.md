# Notes for us:
To whomever is later writing the server part!!!:
To use the authorization method:
```python
import AccessControl from policy.py
ACCESS_CONTROL = AccessControl()
allowed, reason = authorize(user, operation, path)
```
user = user name
operation must be a supported operation (`realpath`, `stat`, `list`, `read`, `write`, `mkdir`, `remove`) -- map SFTP requests to these operations before calling
path = path to the file
example: authorize("alice", "read", "/public/file.txt")

Very important to call the authorize method after jail canonicalization via safe_join
and before any filesystem call!
# Readme

Things to write:
- how to run (on Windows/macOS/Linux), expected outputs, known limitations
- everything else regarding other sections of the project

## Policy

### Loading
After initialisation of AccessControl if any of the data files fails to load properly the server exits and prints an error message. 

### Implementation
A single authorization gate returning True if and only if all 3 (DAC, MAC, RBAC) security systems return True. Every access (deny and allow) is logged in data/audit.jsonl ; For specific implementation read policy.md

### Data Files

**Authentication:**
- `data/users.json` - User credentials (username, salt, hashed password, hash parameters)

**Audit:**
- `data/audit.jsonl` - Access logs (both allowed and denied operations)

**RBAC:**
- `data/user_roles.json` - User → roles mapping
- `data/role_perms.csv` - Role permissions (role, resource, read, write, delete)

**MAC:**
- `data/mac_labels.json` - Clearance levels, user clearances, path classifications

**DAC:**
- `data/dac_owners.csv` - File ownership (path, owner, group, mode)
- `data/user_groups.json` - User → groups mapping

### Rules
TODO: explain the users and their intended purposes

### Self-test
TODO: describe the tests