from oauth_client.client import OAuthClient
def test_authorization_url_contains_state_and_pkce():
    client=OAuthClient("http://127.0.0.1:8000/authorize","lab-client","http://127.0.0.1:5000/callback")
    url,state,verifier=client.build_authorization_url()
    assert "state=" in url and "code_challenge=" in url
    assert state and verifier
