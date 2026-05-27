import os
import requests
from dotenv import load_dotenv

load_dotenv()

token = os.getenv("GITHUB_TOKEN")
headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

params = {
    "ecosystem": "pip",
    "severity": "critical",
    "per_page": 5,
}

response = requests.get(
    "https://api.github.com/advisories",
    headers=headers,
    params=params,
)
response.raise_for_status()
advisories = response.json()

for adv in advisories:
    summary = (adv.get("summary") or "")[:100]
    cvss = adv.get("cvss", {})
    cvss_score = cvss.get("score") if cvss else None
    print(f"GHSA ID:    {adv.get('ghsa_id')}")
    print(f"CVE ID:     {adv.get('cve_id')}")
    print(f"Severity:   {adv.get('severity')}")
    print(f"CVSS Score: {cvss_score}")
    print(f"Summary:    {summary}")
    print("-" * 60)

print(f"\nTotal results returned: {len(advisories)}")
