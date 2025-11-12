import sys, os
import pytest

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
    assert ac.check_dac('alice', 'read', '/reports')[0]
    assert ac.check_dac('alice', 'write', '/reports')[0]

def test_dac_group_read_write(ac):
    """Users in group can read/write with permission, (group: r-)"""
    assert ac.check_dac('bob', 'read', '/reports')[0]
    assert not ac.check_dac('bob', 'write', '/reports')[0]

def test_dac_others_read_write(ac):
    """Others cannot read/write without permission, (other: --)"""
    assert not ac.check_dac('james', 'read', '/reports')[0]
    assert not ac.check_dac('james', 'write', '/reports')[0]

def test_dac_stat(ac):
    """User can use stat only if permission is given
    Owner: x
    Group: -
    Other: x
    """
    assert ac.check_dac('alice', 'stat', '/reports')[0]
    assert not ac.check_dac('bob', 'stat', '/reports')[0]
    assert ac.check_dac('james', 'stat', '/reports')[0]

def test_dac_list_exec_and_read(ac):
    """List requires both read and exec for users, (r-x)"""
    assert ac.check_dac('alice', 'read', '/reports')[0]
    assert ac.check_dac('alice', 'stat', '/reports')[0]
    assert ac.check_dac('alice', 'list', '/reports')[0]

def test_dac_list_no_exec_read_only(ac):
    """List fails if only read but not exec, (r--)"""
    assert ac.check_dac('bob', 'read', '/reports')[0]
    assert not ac.check_dac('bob', 'stat', '/reports')[0]
    assert not ac.check_dac('bob', 'list', '/reports')[0]

def test_dac_list_exec_only_no_read(ac):
    """List fails if only exec but not read, (--x)"""
    assert not ac.check_dac('james', 'read', '/reports')[0]
    assert ac.check_dac('james', 'stat', '/reports')[0]
    assert not ac.check_dac('james', 'list', '/reports')[0]


#MAC TESTS:
#james = public
#alice = internal
#annie = confidential

def test_mac_public_user_read(ac):
    """Public user can read public but not internal/confidential"""
    assert ac.check_mac('james', 'read', '/public/file.txt')[0]
    assert not ac.check_mac('james', 'read', '/internal/file.txt')[0]
    assert not ac.check_mac('james', 'read', '/confidential/secret.txt')[0]

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
    assert ac.check_mac('james', 'write', '/public/file.txt')[0]
    assert not ac.check_mac('james', 'write', '/internal/file.txt')[0]
    assert not ac.check_mac('james', 'write', '/confidential/secret.txt')[0]

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
    assert ac.check_rbac('alice', 'read', '/project')[0]
    assert not ac.check_rbac('alice', 'mkdir', '/project')[0]
    assert not ac.check_rbac('alice', 'write', '/project')[0]
    assert not ac.check_rbac('alice', 'delete', '/project')[0]

def test_rbac_role_full_permissions(ac):
    """Analyst can read,write and delete /project"""
    assert ac.check_rbac('james', 'read', '/project')[0]
    assert ac.check_rbac('james', 'write', '/project')[0]
    assert ac.check_rbac('james', 'mkdir', '/project')[0]
    assert ac.check_rbac('james', 'delete', '/project')[0]

def test_rbac_analyst_no_permissions_for_admin(ac):
    """Analyst alone does not have access to admin"""
    assert not ac.check_rbac('james', 'read', '/admin')[0]
    assert not ac.check_rbac('james', 'write', '/admin')[0]
    assert not ac.check_rbac('james', 'mkdir', '/admin')[0]
    assert not ac.check_rbac('james', 'delete', '/admin')[0]

def test_rbac_full_permission_for_admin(ac):
    """Admin and analyst grants full access to both admin and project"""
    assert ac.check_rbac('annie', 'read', '/admin')[0]
    assert ac.check_rbac('annie', 'write', '/admin')[0]
    assert ac.check_rbac('annie', 'mkdir', '/admin')[0]
    assert ac.check_rbac('annie', 'delete', '/admin')[0]

    assert ac.check_rbac('annie', 'read', '/project')[0]
    assert ac.check_rbac('annie', 'write', '/project')[0]
    assert ac.check_rbac('annie', 'mkdir', '/project')[0]
    assert ac.check_rbac('annie', 'delete', '/project')[0]




# pip install pytest
# to run: pytest tests/policy_tests.py
