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
    """List requires both read and stat for users, (r-x)"""
    assert ac.check_dac('alice', 'read', '/reports')[0]
    assert ac.check_dac('alice', 'stat', '/reports')[0]
    assert ac.check_dac('alice', 'list', '/reports')[0]

def test_dac_list_no_exec_read_only(ac):
    """List fails if only read but not stat, (r--)"""
    assert ac.check_dac('bob', 'read', '/reports')[0]
    assert not ac.check_dac('bob', 'stat', '/reports')[0]
    assert not ac.check_dac('bob', 'list', '/reports')[0]

def test_dac_list_exec_only_no_read(ac):
    """List fails if only stat but not read, (--x)"""
    assert not ac.check_dac('james', 'read', '/reports')[0]
    assert ac.check_dac('james', 'stat', '/reports')[0]
    assert not ac.check_dac('james', 'list', '/reports')[0]


#MAC TESTS:
def test_mac_internal_user_read(ac):
    """Internal user can read public/internal but not confidential"""
    assert ac.check_mac('alice', 'read', '/public/file.txt')[0]
    assert ac.check_mac('alice', 'read', '/internal/file.txt')[0]
    assert not ac.check_mac('alice', 'read', '/confidential/secret.txt')[0]

def test_mac_confidential_user_no_write_down(ac):
    """Confidential user cannot write down to public"""
    assert not ac.check_mac('alice', 'write', '/public/file.txt')[0]
    assert not ac.check_mac('alice', 'write', '/confidential/file.txt')[0]
    assert ac.check_mac('alice', 'write', '/internal/file.txt')[0]

def test_test(ac):
    """Confidential user cannot write down to public"""
    assert not ac.authorize('alice', 'write', '/public/file.txt')[0]

# pip install pytest
# to run: pytest tests/policy_tests.py
