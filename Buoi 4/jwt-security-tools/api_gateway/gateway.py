import os
from flask import Flask, jsonify, request
from jwt_validator.validator import JWTValidator
from token_manager.manager import TokenManager

def create_app(secret=None):
    key=secret or os.getenv("JWT_SECRET")
    if not key: raise RuntimeError("Set JWT_SECRET before starting")
    app=Flask(__name__)
    validator=JWTValidator(key)
    manager=TokenManager(key)
    @app.post("/token")
    def token():
        data=request.get_json(silent=True) or {}
        if data.get("username")!="student" or data.get("password")!="lab-password": return jsonify(error="invalid credentials"),401
        return jsonify(manager.issue("student"))
    @app.post("/refresh")
    def refresh():
        data=request.get_json(silent=True) or {}
        pair=manager.refresh(data.get("refresh_token",""))
        return (jsonify(pair),200) if pair else (jsonify(error="invalid refresh token"),401)
    @app.get("/protected")
    def protected():
        auth=request.headers.get("Authorization","")
        if not auth.startswith("Bearer "): return jsonify(error="bearer token required"),401
        result=validator.validate(auth[7:])
        if not result["valid"]: return jsonify(error="invalid token"),401
        return jsonify(message="authorized",subject=result["claims"].get("sub"))
    return app

if __name__=="__main__": create_app().run(host="127.0.0.1",port=5000,debug=False)
