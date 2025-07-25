import os
import sys
import json
import requests
from requests.auth import HTTPBasicAuth

# === 读取命令行参数 ===
if len(sys.argv) < 7:
    print("Usage: python upload_to_jira.py <user> <api_token> <project_key> <server> <issue_type> <json_file>")
    sys.exit(1)

jira_user = sys.argv[1]
jira_api_token = sys.argv[2]
jira_project_key = sys.argv[3]
jira_server = sys.argv[4]
jira_issue_type = sys.argv[5]
json_file = sys.argv[6]

# === 解析 JSON 文件 ===
try:
    with open(json_file, 'r') as f:
        data = json.load(f)
except FileNotFoundError:
    print(f"❌ Error: File '{json_file}' not found.")
    exit(1)

# === 判断是 Trivy 还是 Semgrep 的输出 ===
def is_trivy_data(data):
    return isinstance(data, list) and all("Vulnerabilities" in item for item in data)

def is_semgrep_data(data):
    return isinstance(data, dict) and "results" in data

# === Jira API 请求函数 ===
def create_jira_issue(summary, description, priority_name="High"):
    url = f"{jira_server}/rest/api/3/issue"
    auth = HTTPBasicAuth(jira_user, jira_api_token)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    payload = {
        "fields": {
            "project": {"key": jira_project_key},
            "summary": summary,
            "description": {
                "content": [{
                    "paragraph": {
                        "text": description,
                        "type": "text"
                    }
                }],
                "type": "doc",
                "version": 1
            },
            "issuetype": {"name": jira_issue_type},
            "priority": {"name": priority_name}
        }
    }

    response = requests.post(url, json=payload, headers=headers, auth=auth)
    if response.status_code in (200, 201):
        print(f"✅ Created Jira issue: {summary}")
    else:
        print(f"❌ Failed to create issue: {summary}")
        print("Status Code:", response.status_code)
        print("Response:", response.text)

# === 解析 Trivy 并创建 Issue ===
def handle_trivy(data):
    priority_map = {
        "CRITICAL": "Highest",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low"
    }

    for result in data:
        if "Vulnerabilities" not in result:
            continue
        for vuln in result["Vulnerabilities"]:
            vulnerability_id = vuln["VulnerabilityID"]
            package_name = vuln["PkgName"]
            severity = vuln["Severity"]
            cvss_score = vuln.get("CVSS", {}).get("nvd", {}).get("v3Score", "N/A")
            fix_version = vuln["FixedVersion"]
            link = vuln["PrimaryLink"]

            summary = f"[{severity}] {vulnerability_id} in {package_name}"
            description = (
                f"**Package:** {package_name}\n"
                f"**Severity:** {severity}\n"
                f"**CVSS Score:** {cvss_score}\n"
                f"**Fix Version:** {fix_version}\n"
                f"**More Info:** [Link to vulnerability]({link})"
            )

            jira_priority = priority_map.get(severity.upper(), "Medium")
            create_jira_issue(summary, description, jira_priority)

# === 解析 Semgrep 并创建 Issue ===
def handle_semgrep(data):
    priority_map = {
        "ERROR": "High",
        "WARNING": "Medium",
        "INFO": "Low"
    }

    for result in data.get("results", []):
        check_id = result["check_id"]
        severity = result["extra"]["severity"]
        message = result["extra"]["message"]
        path = result["path"]
        line = result["start"]["line"]

        summary = f"[{severity}] {check_id}"
        description = (
            f"**File:** {path}:{line}\n"
            f"**Severity:** {severity}\n"
            f"**Message:** {message}"
        )

        jira_priority = priority_map.get(severity.upper(), "Medium")
        create_jira_issue(summary, description, jira_priority)

# === 主逻辑 ===
if is_trivy_data(data):
    handle_trivy(data)
elif is_semgrep_data(data):
    handle_semgrep(data)
else:
    print("❌ Unsupported JSON format. Must be Trivy or Semgrep output.")
    sys.exit(1)