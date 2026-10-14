from token_manager.manager import TokenManager
def test_refresh_token_rotates_and_old_token_is_revoked():
    manager=TokenManager("lab-testing-secret-with-at-least-32-bytes")
    pair=manager.issue("student")
    rotated=manager.refresh(pair["refresh_token"])
    assert rotated and rotated["refresh_token"]!=pair["refresh_token"]
    assert manager.refresh(pair["refresh_token"]) is None
