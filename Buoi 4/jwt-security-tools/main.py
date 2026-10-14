import argparse, os
from api_gateway.gateway import create_app
from jwt_cracker.cracker import JWTCracker
from jwt_validator.validator import JWTValidator

def main():
    parser=argparse.ArgumentParser(description="JWT tools for an authorized local lab")
    parser.add_argument("--check-token")
    parser.add_argument("--crack-token",help="Offline bounded check of a token you own")
    parser.add_argument("--wordlist",help="Local candidate file; first 1000 entries only")
    parser.add_argument("--serve",action="store_true")
    args=parser.parse_args()
    secret=os.getenv("JWT_SECRET")
    if (args.check_token or args.crack_token or args.serve) and not secret: parser.error("Set JWT_SECRET to a strong lab-only secret")
    if args.check_token: print(JWTValidator(secret).validate(args.check_token))
    if args.crack_token:
        candidates=None
        if args.wordlist:
            with open(args.wordlist,encoding="utf-8") as f: candidates=[line.strip() for line in f if line.strip()][:1000]
        print(JWTCracker(candidates).crack(args.crack_token) or "No candidate matched")
    if args.serve: create_app(secret).run(host="127.0.0.1",port=5000,debug=False)

if __name__=="__main__": main()
