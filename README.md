# Notes for us:
To whomever is later writing the server part!!!:
To use the authorization method:
```python
import AccessControl from policy.py
ACCESS_CONTROL = AccessControl()
allowed, audit_log = authorize(user, operation, path)
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
Roles and clearance levels of users are defined as follows:
| **User**   | **Roles**      | **Clearance Level** | **Ownership**                          |
|------------|----------------|---------------------|----------------------------------------|
| **Alice**  | Intern         | Internal            | Owner of *reports*                     |
| **Bob**    | Intern         | Public              | —                                      |
| **James**  | Analyst        | Internal            | Owner of *project*                     |
| **Annie**  | Admin, Analyst | Confidential        | Owner of *admin*, *text*, and *policy* |

read/write permissions of each users are defined as followed:
| **File**    | **Alice (Intern)** | **Bob (Intern)** | **James (Analyst)** | **Annie (Admin, Analyst)** |
|-------------|--------------------|------------------|---------------------|----------------------------|
| **reports** | Read / Write       | Read             | -                   | -                          |
| **admin**   | -                  | -                | -                   | Read / Write               |
| **text**    | -                  | -                | -                   | Read / Write               |
| **project** | -                  | -                | Read / Write        | Read / Write               |
| **policy**  | -                  | -                | -                   | Read / Write               |


### Self-test
# Access Control Test Plan

This section describes the tests used to validate DAC, MAC, RBAC, composite tests and audits

# Access Control Test Plan

This section outlines what each test verifies for **DAC**, **MAC**, **RBAC**, **composite policies**, and **audit logging**.

---

## 1. DAC (Discretionary Access Control) Tests

These tests check that:

- The **file owner** can successfully **read and write** their own files.  
- **Non-owners** cannot **write** to files unless explicitly granted permission.  
- The **execute bit** on a directory properly controls the ability to **list (ls)** or **inspect (stat)** its contents.  
- Removing the execute bit denies file listing.

---

## 2. MAC (Mandatory Access Control) Tests

These tests verify that:

- A user with **Internal clearance** can **read** files classified as *Public* or *Internal*, but is **denied access** to *Confidential* files.  
- A user with **Confidential clearance** **cannot write down** to *Public* files or directories (to prevent data leaks).  
- The **read-up, no write-down** rule is consistently enforced across all MAC-protected resources.

---

## 3. RBAC (Role-Based Access Control) Tests

These tests confirm that:

- Users with the **Analyst** role can **read and write** under `/projects`.  
- Analysts **cannot create directories** under `/admin` unless given the **Admin** role.  
- Adding the **Admin** role grants **directory creation and modification privileges** under `/admin`.  
- If **per-user deny rules** are configured, those **override** any role-based allow permissions.

---

## 4. Composite Policy Tests

These tests ensure that:

- When **DAC allows** but **MAC denies** (or vice versa), the **final decision** matches the defined **policy composition rule**.  
- Combined access control logic is applied consistently, even in edge cases.  
- At least one **directory traversal attempt** is correctly **denied** due to the intersection of DAC and MAC restrictions.

---

## 5. Audit Assertions

These tests verify that:

- Every **allow** and **deny** decision **generates an audit record**.  
- Each audit log entry contains the required fields:  
  - **User** – the acting user  
  - **Action** – the operation attempted (e.g., read, write, mkdir)  
  - **Target** – the file or directory involved  
  - **Decision** – whether the action was allowed or denied  
  - **Policy Source** – which policy (DAC, MAC, RBAC, composite) determined the outcome  
- Logs are consistent, complete, and traceable for all access decisions.

---
