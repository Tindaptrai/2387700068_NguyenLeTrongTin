import time
import jwt

class JWTValidator:
    def __init__(self,secret):
        if not secret: raise ValueError("Signing secret required")
        self.secret=secret
    def issue_for_test(self,claims):
        now=int(time.time())
        return jwt.encode({**claims,"iat":now,"exp":now+300},self.secret,algorithm="HS256")
    def validate(self,token):
        try:
            claims=jwt.decode(token,self.secret,algorithms=["HS256"],options={"require":["exp"]},leeway=0)
            return {"valid":True,"claims":claims,"header":jwt.get_unverified_header(token),"issues":[]}
        except jwt.PyJWTError as exc:
            return {"valid":False,"claims":{},"header":{},"issues":[str(exc)]}
