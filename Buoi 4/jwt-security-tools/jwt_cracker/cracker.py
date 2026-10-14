import jwt

class JWTCracker:
    # Offline exercise only; candidate lists are deliberately capped.
    def __init__(self,candidates=None): self.candidates=(candidates or ["password","secret","lab-secret"])[:1000]
    def crack(self,token):
        for candidate in self.candidates:
            try:
                jwt.decode(token,candidate,algorithms=["HS256"],options={"verify_exp":False})
                return candidate
            except jwt.PyJWTError: pass
        return None
