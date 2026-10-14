from jwt_cracker.cracker import JWTCracker
from jwt_validator.validator import JWTValidator
def test_cracker_finds_key_from_local_candidate_list():
    token=JWTValidator("lab-testing-secret-with-at-least-32-bytes").issue_for_test({"sub":"student"})
    assert JWTCracker(["wrong-candidate-secret-with-32-bytes-long","lab-testing-secret-with-at-least-32-bytes"]).crack(token)=="lab-testing-secret-with-at-least-32-bytes"
