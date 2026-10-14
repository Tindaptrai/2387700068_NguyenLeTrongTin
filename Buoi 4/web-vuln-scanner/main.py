import argparse
import requests
from scanners.csrf_detector import CSRFDetector
from scanners.sql_injection_tester import SQLInjectionTester
from scanners.ssrf_tester import SSRFTester
from scanners.xss_scanner import XSSScanner
from report.report_generator import ReportGenerator

def scan(url):
    findings=[]
    for scanner in (XSSScanner(), SQLInjectionTester(), CSRFDetector(), SSRFTester()):
        try: findings.extend(scanner.scan(url))
        except (ValueError, OSError, requests.RequestException) as exc: findings.append({"type":"scan_error","severity":"info","url":url,"description":str(exc)})
    return findings

def main():
    parser=argparse.ArgumentParser(description="Authorized local web lab scanner")
    parser.add_argument("url",help="URL of your local or authorized lab app")
    parser.add_argument("--output",default="report.json")
    args=parser.parse_args()
    findings=scan(args.url)
    ReportGenerator().save(findings,args.output)
    print(f"Wrote {len(findings)} finding(s) to {args.output}")

if __name__=="__main__": main()
