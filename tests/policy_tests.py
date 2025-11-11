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

def test_mac_internal_user_read(ac):
    """Internal user can read public/internal but not confidential"""
    assert ac.check_mac('alice', 'read', '/public/file.txt')[0]
    assert ac.check_mac('alice', 'read', '/internal/file.txt')[0]
    assert not ac.check_mac('alice', 'read', '/confidential/secret.txt')[0]

def test_mac_confidential_user_no_write_down(ac):
    """Confidential user cannot write down to public"""
    assert not ac.check_mac('alice', 'write', '/public/file.txt')[0]
    assert ac.check_mac('alice', 'write', '/confidential/file.txt')[0]

# pip install pytest
# to run: pytest tests/policy_tests.py
