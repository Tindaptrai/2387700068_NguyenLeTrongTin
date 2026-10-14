from api_gateway.gateway import create_app
def test_gateway_allows_valid_token_and_rejects_missing_token():
    app=create_app("lab-testing-secret-with-at-least-32-bytes").test_client()
    assert app.get("/protected").status_code==401
    token=app.post("/token",json={"username":"student","password":"lab-password"}).get_json()["access_token"]
    assert app.get("/protected",headers={"Authorization":f"Bearer {token}"}).status_code==200
