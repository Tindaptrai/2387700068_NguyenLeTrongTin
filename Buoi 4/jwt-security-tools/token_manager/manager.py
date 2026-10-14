import hashlib, secrets, time
import jwt

class TokenManager:
    def __init__(self,secret,access_seconds=300):
        if not secret: raise ValueError("Signing secret required")
        self.secret=secret
        self.access_seconds=access_seconds
        self._refresh_tokens={}
    @staticmethod
    def _digest(token): return hashlib.sha256(token.encode()).hexdigest()
    def issue(self,subject):
        now=int(time.time())
        access=jwt.encode({"sub":subject,"iat":now,"exp":now+self.access_seconds},self.secret,algorithm="HS256")
        refresh=secrets.token_urlsafe(32)
        self._refresh_tokens[self._digest(refresh)]=subject
        return {"access_token":access,"refresh_token":refresh,"token_type":"Bearer","expires_in":str(self.access_seconds)}
    def refresh(self,refresh_token):
        subject=self._refresh_tokens.pop(self._digest(refresh_token),None)
        return self.issue(subject) if subject else None
    def revoke(self,refresh_token): return self._refresh_tokens.pop(self._digest(refresh_token),None) is not None
