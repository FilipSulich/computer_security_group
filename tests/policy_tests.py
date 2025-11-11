import sys, os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server'))
os.chdir(os.path.join(os.path.dirname(__file__), '..'))

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
    assert not ac.check_mac('bob', 'write', '/public/file.txt')[0]
    assert ac.check_mac('bob', 'write', '/confidential/file.txt')[0]

# pip install pytest
# to run: pytest tests/policy_tests.py
# the test doesnt work btw
