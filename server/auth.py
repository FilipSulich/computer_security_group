# ex 1.3
# to test the username-password function run with: python server/auth.py 

import hashlib
import hmac
import time
import json
import os
from datetime import datetime
from typing import Optional, Dict
from collections import defaultdict

# Try to use argon2-cffi (recommended), fall back to scrypt
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, InvalidHash
    USE_ARGON2 = True
    ph = PasswordHasher(
        time_cost=2,        # iterations
        memory_cost=65536,  # 64 MB
        parallelism=1,      # threads
        hash_len=32,        # output length
        salt_len=16         # salt length
    )
except ImportError:
    USE_ARGON2 = False
    print("Warning: argon2-cffi not installed. Using scrypt fallback.")
    print("Install with: pip install argon2-cffi")


# Configuration
PEPPER = os.environ.get('SFTP_PEPPER', 'change-this-secret-pepper-in-production')
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5 minutes in seconds
RATE_LIMIT_WINDOW = 60  # 1 minute
MAX_ATTEMPTS_PER_WINDOW = 10
AUDIT_LOG_PATH = os.path.join(os.path.dirname(__file__), 'audit_auth.jsonl')

# In-memory tracking (in production, use Redis or database)
_failed_attempts: Dict[str, int] = defaultdict(int)
_lockout_until: Dict[str, float] = {}
_rate_limit_tracker: Dict[str, list] = defaultdict(list)


# password hashing using Argon2id
def hash_password(password: str) -> str:

    # Add pepper before hashing
    peppered = password + PEPPER
    
    if USE_ARGON2:
        return ph.hash(peppered)
    else:
        # Scrypt fallback
        salt = os.urandom(16)
        # scrypt params: N=16384, r=8, p=1 (moderate security)
        key = hashlib.scrypt(
            peppered.encode('utf-8'),
            salt=salt,
            n=16384,
            r=8,
            p=1,
            dklen=32
        )
        # Format: scrypt$salt_hex$hash_hex
        return f"scrypt${salt.hex()}${key.hex()}"

# verifies password againts its hash
def verify_password(password: str, password_hash: str) -> bool:

    peppered = password + PEPPER
    
    try:
        if USE_ARGON2:
            ph.verify(password_hash, peppered)
            # Check if rehashing is needed (params changed)
            if ph.check_needs_rehash(password_hash):
                # In production: update user's hash in database
                pass
            return True
        else:
            # Parse scrypt hash
            if not password_hash.startswith('scrypt$'):
                return False
            _, salt_hex, hash_hex = password_hash.split('$')
            salt = bytes.fromhex(salt_hex)
            stored_hash = bytes.fromhex(hash_hex)
            
            # Compute hash with same params
            key = hashlib.scrypt(
                peppered.encode('utf-8'),
                salt=salt,
                n=16384,
                r=8,
                p=1,
                dklen=32
            )
            # Constant-time comparison
            return hmac.compare_digest(key, stored_hash)
    
    except (VerifyMismatchError, InvalidHash, ValueError):
        return False

# Path to user database file
USER_DATABASE_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'users.json')

def load_users() -> list:
    """Load users from JSON file (returns array)"""
    try:
        with open(USER_DATABASE_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: User database not found at {USER_DATABASE_PATH}")
        return []
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in user database: {e}")
        return []

def save_users(users: list):
    """Save users to JSON file (saves as array)"""
    os.makedirs(os.path.dirname(USER_DATABASE_PATH), exist_ok=True)
    with open(USER_DATABASE_PATH, 'w') as f:
        json.dump(users, f, indent=2)

def get_user(username: str) -> Optional[dict]:
    """Retrieve user from JSON database (searches array)"""
    users = load_users()
    for user in users:
        if user.get('username') == username:
            return user
    return None

# checks if user has exceeded rate limit
def check_rate_limit(username: str) -> bool:

    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW
    
    # Remove old attempts outside the window
    _rate_limit_tracker[username] = [
        t for t in _rate_limit_tracker[username] if t > cutoff
    ]
    
    # Check if over limit
    if len(_rate_limit_tracker[username]) >= MAX_ATTEMPTS_PER_WINDOW:
        return False
    
    # Record this attempt
    _rate_limit_tracker[username].append(now)
    return True

# checks if account is locked out
def is_locked_out(username: str) -> bool:
    """Check if account is locked out"""
    if username in _lockout_until:
        if time.time() < _lockout_until[username]:
            return True
        else:
            # Lockout expired, clear it
            del _lockout_until[username]
            _failed_attempts[username] = 0
    return False

# records a failed login attempt
def record_failed_attempt(username: str):

    _failed_attempts[username] += 1
    
    if _failed_attempts[username] >= MAX_FAILED_ATTEMPTS:
        # Lock out the account
        _lockout_until[username] = time.time() + LOCKOUT_DURATION
        audit_log(username, 'lockout', success=False, 
                  reason=f'Too many failed attempts ({MAX_FAILED_ATTEMPTS})')


# clears failed attempts on successful login
def record_successful_attempt(username: str):

    _failed_attempts[username] = 0
    if username in _lockout_until:
        del _lockout_until[username]


# logs authentication events to audit_auth.jsonl
def audit_log(username: str, event_type: str, success: bool, reason: str = ''):

    try:
        os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
        
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'username': username,
            'event': event_type,
            'success': success,
            'reason': reason,
            'source': 'auth'
        }
        
        with open(AUDIT_LOG_PATH, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    except Exception as e:
        # Don't let audit failures break authentication
        print(f"Warning: Failed to write audit log: {e}")

"""
Main authentication function

    Security features: 
    - Argon2id password hashing (or scrypt fallback)
    - Salt (per-password, handled by Argon2/scrypt)
    - Pepper (application-wide secret)
    - Rate limiting (per user)
    - Account lockout after failed attempts
    - Audit logging
"""
def validate_user_password(username: str, password: str):
    
    # 1 - Check rate limit
    if not check_rate_limit(username):
        audit_log(username, 'login', success=False, reason='Rate limited')
        return False
    
    # 2 - Check if account is locked out
    if is_locked_out(username):
        remaining = int(_lockout_until[username] - time.time())
        audit_log(username, 'login', success=False, 
                  reason=f'Account locked (unlocks in {remaining}s)')
        return False
    
    # 3 - Get user from database
    user = get_user(username)
    if not user:
        # User doesn't exist - still check password to prevent timing attacks
        # (but use a dummy hash)
        verify_password(password, hash_password('dummy'))
        audit_log(username, 'login', success=False, reason='User not found')
        return False
    
    # 4 - Check if account is active
    if not user.get('active', False):
        audit_log(username, 'login', success=False, reason='Account disabled')
        return False
    
    # 5 - Verify password
    # Reconstruct full hash from stored salt and hash parts
    salt = user.get('salt', '')
    hash_part = user.get('password_hash', '')

    if USE_ARGON2:
        # Reconstruct Argon2 format: $argon2id$v=19$m=65536,t=2,p=1$<salt>$<hash>
        password_hash = f"$argon2id$v=19$m=65536,t=2,p=1${salt}${hash_part}"
    else:
        # Reconstruct scrypt format: scrypt$<salt>$<hash>
        password_hash = f"scrypt${salt}${hash_part}"

    if verify_password(password, password_hash):
        # Success!
        record_successful_attempt(username)
        audit_log(username, 'login', success=True, reason='Valid credentials')
        return True
    else:
        # Failed authentication
        record_failed_attempt(username)
        audit_log(username, 'login', success=False, reason='Invalid password')
        return False


# testing/debugging functions
if __name__ == "__main__":
    import getpass
    import sys
    
    print("=== Authentication Module Test ===\n")
    print(f"Using: {'Argon2id' if USE_ARGON2 else 'scrypt (fallback)'}")
    print(f"Pepper configured: {'Yes' if PEPPER != 'change-this-secret-pepper-in-production' else 'No (using default!)'}\n")
    print("Available users: bob, alice, james, annie")
    print("Type 'quit' or 'exit' to stop")
    print("Type 'setup' to create test users\n")
    
    # Interactive testing loop
    attempt_count = 0
    while True:
        try:
            # Get username
            username = input("Username: ").strip()
            
            if username.lower() in ('quit', 'exit', 'q'):
                print("\nExiting...")
                break
        
            if not username:
                continue
            
            # Get password (hidden input)
            password = getpass.getpass("Password: ")
            
            # Validate
            attempt_count += 1
            print(f"\n[Attempt {attempt_count}] Authenticating '{username}'...")
            result = validate_user_password(username, password)
            
            if result:
                print(f"✓ Authentication SUCCESSFUL for '{username}'")
                user = get_user(username)
                if user:
                    print(f"  Status: {'Active' if user.get('active') else 'Inactive'}")
            else:
                print(f"✗ Authentication FAILED for '{username}'")
                
                # Show helpful info
                if get_user(username):
                    if is_locked_out(username):
                        remaining = int(_lockout_until.get(username, 0) - time.time())
                        print(f"  ⚠ Account is LOCKED OUT (unlocks in {remaining}s)")
                    else:
                        failed = _failed_attempts.get(username, 0)
                        remaining_attempts = MAX_FAILED_ATTEMPTS - failed
                        if remaining_attempts > 0:
                            print(f"  Failed attempts: {failed}/{MAX_FAILED_ATTEMPTS}")
                            print(f"  {remaining_attempts} attempts remaining before lockout")
                else:
                    print(f"  User '{username}' does not exist")
            
            print()
        
        except KeyboardInterrupt:
            print("\n\nInterrupted. Exiting...")
            break
        except EOFError:
            print("\n\nExiting...")
            break
    
    print(f"\nTotal authentication attempts: {attempt_count}")
    print(f"Audit log written to: {AUDIT_LOG_PATH}")
    print("\nRun with: python server/auth.py")