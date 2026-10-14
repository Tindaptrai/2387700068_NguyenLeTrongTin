import base64, hashlib, secrets
from urllib.parse import urlencode, urlparse
import requests

class OAuthClient:
    def __init__(self,authorization_endpoint,client_id,redirect_uri,token_endpoint=None):
        self.authorization_endpoint=authorization_endpoint
        self.client_id=client_id
        self.redirect_uri=redirect_uri
        self.token_endpoint=token_endpoint
        self._check_endpoint(authorization_endpoint)
        if token_endpoint: self._check_endpoint(token_endpoint)
    @staticmethod
    def _check_endpoint(url):
        p=urlparse(url)
        local=p.hostname in {"localhost","127.0.0.1","::1"}
        if p.scheme!="https" and not (p.scheme=="http" and local):
            raise ValueError("OAuth endpoint must use HTTPS or localhost for lab")
    def build_authorization_url(self):
        state=secrets.token_urlsafe(24)
        verifier=secrets.token_urlsafe(48)
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        query=urlencode({"response_type":"code","client_id":self.client_id,"redirect_uri":self.redirect_uri,"scope":"openid profile","state":state,"code_challenge":challenge,"code_challenge_method":"S256"})
        sep="&" if "?" in self.authorization_endpoint else "?"
        return self.authorization_endpoint+sep+query,state,verifier
    def exchange_code(self,code,verifier,client_secret=None):
        if not self.token_endpoint: raise ValueError("token_endpoint is required")
        data={"grant_type":"authorization_code","code":code,"redirect_uri":self.redirect_uri,"client_id":self.client_id,"code_verifier":verifier}
        auth=(self.client_id,client_secret) if client_secret else None
        response=requests.post(self.token_endpoint,data=data,auth=auth,timeout=5,allow_redirects=False)
        response.raise_for_status()
        return response.json()
