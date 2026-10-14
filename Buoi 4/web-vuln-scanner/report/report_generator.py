import json
from datetime import datetime, timezone

class ReportGenerator:
    def generate(self, findings):
        return json.dumps({"generated_at":datetime.now(timezone.utc).isoformat(),"author":"Nguyen Le Trong Tin","finding_count":len(findings),"findings":findings},ensure_ascii=False,indent=2)
    def save(self, findings, path):
        with open(path,"w",encoding="utf-8") as stream: stream.write(self.generate(findings))
