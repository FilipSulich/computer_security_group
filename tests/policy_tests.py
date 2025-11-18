import sys, os
import pytest
from datetime import datetime, timedelta

# pip install pytest
# to run: pytest tests/policy_tests.py


# Change to server directory so ../data/ paths work correctly
server_dir = os.path.join(os.path.dirname(__file__), '..', 'server')
os.chdir(server_dir)
sys.path.insert(0, server_dir)

from policy import AccessControl

@pytest.fixture
def ac():
    return AccessControl()

#DAC TESTS:
#The file: '/reports' has mode 0o741
#Owner: rwx
#Group: r--
#Other: --x (for testing purposes, in real-life a user no permissions should not be able to successfully stat a private file.)

def test_dac_owner_read_write(ac):
    """Owner can read/write file, (owner: rw) """
    assert ac.check_dac('alice', 'read', '/public/reports')[0]
    assert ac.check_dac('alice', 'write', '/public/reports')[0]

def test_dac_group_read_write(ac):
    """Users in group can read/write with permission, (group: r-)"""
    assert ac.check_dac('bob', 'read', '/public/reports')[0]
    assert not ac.check_dac('bob', 'write', '/public/reports')[0]

def test_dac_others_read_write(ac):
    """Others cannot read/write without permission, (other: --)"""
    assert not ac.check_dac('james', 'read', '/public/reports')[0]
    assert not ac.check_dac('james', 'write', '/public/reports')[0]

def test_dac_stat(ac):
    """User can use stat only if permission is given
    Owner: x
    Group: -
    Other: x
    """
    assert ac.check_dac('alice', 'stat', '/public/reports')[0]
    assert not ac.check_dac('bob', 'stat', '/public/reports')[0]
    assert ac.check_dac('james', 'stat', '/public/reports')[0]

def test_dac_list_exec_and_read(ac):
    """List requires both read and exec for users, (r-x)"""
    assert ac.check_dac('alice', 'read', '/public/reports')[0]
    assert ac.check_dac('alice', 'stat', '/public/reports')[0]
    assert ac.check_dac('alice', 'list', '/public/reports')[0]

def test_dac_list_no_exec_read_only(ac):
    """List fails if only read but not exec, (r--)"""
    assert ac.check_dac('bob', 'read', '/public/reports')[0]
    assert not ac.check_dac('bob', 'stat', '/public/reports')[0]
    assert not ac.check_dac('bob', 'list', '/public/reports')[0]

def test_dac_list_exec_only_no_read(ac):
    """List fails if only exec but not read, (--x)"""
    assert not ac.check_dac('james', 'read', '/public/reports')[0]
    assert ac.check_dac('james', 'stat', '/public/reports')[0]
    assert not ac.check_dac('james', 'list', '/public/reports')[0]


#MAC TESTS:
#bob = public
#alice = internal
#annie = confidential

def test_mac_public_user_read(ac):
    """Public user can read public but not internal/confidential"""
    assert ac.check_mac('bob', 'read', '/public/file.txt')[0]
    assert not ac.check_mac('bob', 'read', '/internal/file.txt')[0]
    assert not ac.check_mac('bob', 'read', '/confidential/secret.txt')[0]

def test_mac_internal_user_read(ac):
    """Internal user can read public/internal but not confidential"""
    assert ac.check_mac('alice', 'read', '/public/file.txt')[0]
    assert ac.check_mac('alice', 'read', '/internal/file.txt')[0]
    assert not ac.check_mac('alice', 'read', '/confidential/secret.txt')[0]

def test_mac_confidential_user_read(ac):
    """confidential user can read everything"""
    assert ac.check_mac('annie', 'read', '/public/file.txt')[0]
    assert ac.check_mac('annie', 'read', '/internal/file.txt')[0]
    assert ac.check_mac('annie', 'read', '/confidential/secret.txt')[0]

def test_mac_public_user_write(ac):
    """Public user can write public but not internal/confidential"""
    assert ac.check_mac('bob', 'write', '/public/file.txt')[0]
    assert not ac.check_mac('bob', 'write', '/internal/file.txt')[0]
    assert not ac.check_mac('bob', 'write', '/confidential/secret.txt')[0]

def test_mac_internal_user_write(ac):
    """Internal user can write internal but not up to confidential or down to public"""
    assert not ac.check_mac('alice', 'write', '/public/file.txt')[0]
    assert ac.check_mac('alice', 'write', '/internal/file.txt')[0]
    assert not ac.check_mac('alice', 'write', '/confidential/secret.txt')[0]

def test_mac_confidential_user_no_write_down(ac):
    """Confidential user cannot write down to public/internal"""
    assert not ac.check_mac('annie', 'write', '/public/file.txt')[0]
    assert not ac.check_mac('annie', 'write', '/internal/file.txt')[0]
    assert ac.check_mac('annie', 'write', '/confidential/file.txt')[0]

#RBAC:
#alice = intern, only read project and no access admin file
#james = analyst, read/write/delete/mkdir project and no access admin file
#alice = admin and analyst, read/write/delete/mkdir project and read/write/delete admin file

def test_rbac_role_not_full_permissions(ac):
    """Intern can read, but not write or delete /project"""
    assert ac.check_rbac('alice', 'read', '/internal/project')[0]
    assert not ac.check_rbac('alice', 'mkdir', '/internal/project')[0]
    assert not ac.check_rbac('alice', 'write', '/internal/project')[0]
    assert not ac.check_rbac('alice', 'delete', '/internal/project')[0]

def test_rbac_role_full_permissions(ac):
    """Analyst can read,write and delete /project"""
    assert ac.check_rbac('james', 'read', '/internal/project')[0]
    assert ac.check_rbac('james', 'write', '/internal/project')[0]
    assert ac.check_rbac('james', 'mkdir', '/internal/project')[0]
    assert ac.check_rbac('james', 'delete', '/internal/project')[0]

def test_rbac_analyst_no_permissions_for_admin(ac):
    """Analyst alone does not have access to admin"""
    assert not ac.check_rbac('james', 'read', '/confidential/admin')[0]
    assert not ac.check_rbac('james', 'write', '/confidential/admin')[0]
    assert not ac.check_rbac('james', 'mkdir', '/confidential/admin')[0]
    assert not ac.check_rbac('james', 'delete', '/confidential/admin')[0]

def test_rbac_full_permission_for_admin(ac):
    """Admin and analyst grants full access to both admin and project"""
    #check access for admin, requires admin role
    assert ac.check_rbac('annie', 'read', '/confidential/admin')[0]
    assert ac.check_rbac('annie', 'write', '/confidential/admin')[0]
    assert ac.check_rbac('annie', 'mkdir', '/confidential/admin')[0]
    assert ac.check_rbac('annie', 'delete', '/confidential/admin')[0]

    #chekc access for project, requires analyst role
    assert ac.check_rbac('annie', 'read', '/internal/project')[0]
    assert ac.check_rbac('annie', 'write', '/internal/project')[0]
    assert ac.check_rbac('annie', 'mkdir', '/internal/project')[0]
    assert ac.check_rbac('annie', 'delete', '/internal/project')[0]


#COMPOSITE TESTS
def test_composite_test_allow_by_all(ac):
    """If user is allowed an operation by dac,mac and rbac, system gives permission"""
    assert ac.authorize('annie', 'read', '/confidential/admin')[0]
    assert ac.authorize('annie', 'write', '/confidential/admin')[0]

def test_composite_test_deny_by_all(ac):
    """If user is denied by dac,mac,rbac, system denies access"""
    assert not ac.authorize('alice', 'read', '/confidential/admin')[0]
    assert not ac.authorize('alice', 'write', '/confidential/admin')[0]

def test_composite_test_deny_dac_only(ac):
    """If user is denied by dac, but allowed by mac,rbac, system denies access"""
    #check if system denies access
    assert not ac.authorize('bob', 'read', '/public/policy')[0]
    assert not ac.authorize('bob', 'write', '/public/policy')[0]

    #check individual methods ( should return: dac: false, mac: true, rbac: true)
    assert not ac.check_dac('bob', 'read', '/public/policy')[0]
    assert not ac.check_dac('bob', 'write', '/public/policy')[0]
    assert ac.check_mac('bob', 'read', '/public/policy')[0]
    assert ac.check_mac('bob', 'write', '/public/policy')[0]
    assert ac.check_rbac('bob', 'read', '/public/policy')[0]
    assert ac.check_rbac('bob', 'write', '/public/policy')[0]

def test_composite_test_deny_mac_only(ac):
    """If user is denied by mac, but allowed by dac,rbac, system denies access"""
    # check if system denies access
    assert not ac.authorize('alice', 'read', '/confidential/text')[0]
    assert not ac.authorize('alice', 'write', '/confidential/text')[0]

    # check individual methods (should return: dac: true, mac: false, rbac: true)
    assert ac.check_dac('alice', 'read', '/confidential/text')[0]
    assert ac.check_dac('alice', 'write', '/confidential/text')[0]
    assert not ac.check_mac('alice', 'read', '/confidential/text')[0]
    assert not ac.check_mac('alice', 'write', '/confidential/text')[0]
    assert ac.check_rbac('alice', 'read', '/confidential/text')[0]
    assert ac.check_rbac('alice', 'write', '/confidential/text')[0]


#AUDIT ASSERTION TESTS:
def test_audit_allowed_action(ac):
    """Verify audit record for an allowed operation."""
    #input for an allowed operation (alice (owner) reads public file)
    user = 'alice'
    operation = 'read'
    path = '/public/reports'
    expected_reason = 'Allowed by all policies'

    decision, record = ac.authorize(user, operation, path)

    #check if decision is allowed by system
    assert decision is True

    #check if audit fields match
    assert record['user'] == user
    assert record['operation'] == operation
    assert record['path'] == path
    assert record['allowed'] is True
    assert record['reason'] == expected_reason

def test_audit_timestamp(ac):
    """Verify audit timestamp, both format and time range."""
    #save start and end time of call to authorize
    start_time = datetime.now()
    record = ac.authorize('alice', 'read', '/public/reports')[1]
    end_time = datetime.now()

    #check if audit timestamp has correct format
    try:
        logged_time = datetime.fromisoformat(record['timestamp'])
    except ValueError as e:
        pytest.fail(f"Timestamp is not in valid ISO 8601 format: {e}")

    #check if audit timestamp falls within the range of the start/end time of call to authorize
    assert logged_time >= start_time - timedelta(milliseconds=50)
    assert logged_time <= end_time + timedelta(milliseconds=50)

def test_audit_denied_action(ac):
    """Verify audit record for a denied operation."""

    #input for an allowed operation (james (other) reads public file with no read/write for others)
    user = 'james'
    operation = 'read'
    path = '/public/reports'
    expected_reason = 'DAC: DENY, other lacks permission on /public/reports (mode=0o741) | MAC: ALLOW | RBAC: ALLOW'

    decision, record = ac.authorize(user, operation, path)

    #check if access is denied
    assert decision is False

    #check if audit fields match
    assert record['user'] == user
    assert record['operation'] == operation
    assert record['path'] == path
    assert record['allowed'] is False
    assert record['reason'] == expected_reason
