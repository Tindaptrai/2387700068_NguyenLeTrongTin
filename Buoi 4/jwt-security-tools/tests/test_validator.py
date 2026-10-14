from jwt_validator.validator import JWTValidator
def test_rejects_malformed_token():
    assert not JWTValidator("lab-testing-secret-with-at-least-32-bytes").validate("not.a.jwt")["valid"]
def test_round_trip_token_is_valid():
    validator=JWTValidator("lab-testing-secret-with-at-least-32-bytes")
    assert validator.validate(validator.issue_for_test({"sub":"student"}))["valid"]
