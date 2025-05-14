Advanced Security Projects for GitHub


# ============================
# 2️⃣ Detection Lifecycle Automation (Python)
# ============================
# Goal: Automate detection-to-alert-to-SOAR process

import json

# This function creates an alert definition payload
# Inputs: query name and a result threshold
# Output: dictionary with alert title, condition, linked search, and SOAR action name

def create_alert_payload(query_name, threshold):  # Can be tied to Splunk alert API or saved search automation endpoint  # Generates a JSON payload for alerting systems
    return {
        "title": f"Detection: {query_name}",
        "trigger_condition": f"count > {threshold}",
        "search_query": f"savedsearch:{query_name}",
        "severity": "medium",
        "actions": ["SOAR-playbook-X"]
    }

# Sample usage:
# Converts a saved SPL search into a JSON object that can be sent to Splunk or SOAR
# alert = create_alert_payload("RDP_Failed_Logons", 5)
# print(json.dumps(alert, indent=2))


# ============================
# 3️⃣ Alert Enrichment Platform (Python)
# ============================
# Goal: Enrich IP address with VirusTotal & AbuseIPDB threat intel

import requests

# This function enriches an IP with context from VT and AbuseIPDB
# Returns key attributes like malicious score and country of origin

def enrich_ip(ip):  # Connects to Splunk SOAR or Phantom as an alert enrichment block
    vt_key = "REPLACE_VT_API"
    ab_key = "REPLACE_AB_API"

    vt = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",  # Sends a request to VirusTotal API/api/v3/ip_addresses/{ip}",
                      headers={"x-apikey": vt_key}).json()
    ab = requests.get("https://api.abuseipdb.com/api/v2/check",  # Sends a request to AbuseIPDB API",
                      headers={"Key": ab_key, "Accept": "application/json"},
                      params={"ipAddress": ip}).json()

    return {
        "ip": ip,
        "vt_malicious": vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
        "abuse_score": ab.get("data", {}).get("abuseConfidenceScore", 0)
    }

# Used for: Adding context to alerts to improve prioritization and incident response
# enrich_ip("8.8.8.8")


# ============================
# 4️⃣ Risk-Based Alerting (Python)
# ============================
# Goal: Assign severity to alerts based on logic like role, time, and location

# Risk weights map each risk signal to a numeric score
risk_weights = {
    "admin_account": 30,
    "off_hours": 20,
    "foreign_country": 25
}

# Assigns a score based on multiple contextual risk signals from the alert

def assign_risk(alert):  # Designed to plug into a SOAR playbook for contextual alert scoring
    score = 0
    if alert.get("user_role") == "admin":  # Adds score if account is privileged score += risk_weights["admin_account"]
    if alert.get("hour") < 6 or alert.get("hour") > 22:  # Adds score if login occurred off-hours score += risk_weights["off_hours"]
    if alert.get("country") not in ["US", "CA"]:  # Adds score if login is from non-approved countries score += risk_weights["foreign_country"]
    alert["risk_score"] = score
    return alert

# Used for: Prioritizing alerts based on contextual severity
# assign_risk({"user_role": "admin", "hour": 2, "country": "RU"})


# ============================
# 5️⃣ Incident Triage + Enrichment (SOAR Style)
# ============================
# Goal: Simulate alert ingestion → enrichment → ticket creation in IR workflow

# Uses the enrichment function from earlier to get IP context
# Simulates IR logic and prints ticket creation steps

def incident_workflow(ip):  # Connects to Splunk SOAR, XSOAR, or custom IR workflow for end-to-end triage
    details = enrich_ip(ip)  # Enriches alert with threat intelligence scores
    print(f"Triage Result for {ip} → Risk: {details['vt_malicious']} VT | {details['abuse_score']} AbuseIPDB")
    print("Creating ticket in ServiceNow...")  # Simulates sending an incident to ticketing system
    # Simulated API call
    print("Ticket ID: INC1234567 created.")

# Used for: Replicating SOAR/IR automation logic for ticketed workflows
# incident_workflow("8.8.8.8")


# ============================
# 6️⃣ Generative AI Security Assistant (Concept)
# ============================
# Goal: Summarize log lines and suggest MITRE ATT&CK mapping using LLM

import openai

# Sends a prompt to GPT to analyze logs and return a summary with TTP mappings
# This can support SOC analysts during triage

def summarize_alert(logs):  # Connects to an internal GPT-powered SOC tool or SOAR enrichment block
    openai.api_key = "REPLACE_YOUR_API_KEY"
    prompt = f"Analyze these logs and summarize what the attacker did. Also map to a MITRE tactic: {logs}"  # LLM prompt for security summarization what the attacker did. Also map to a MITRE tactic: {logs}"
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    print(response.choices[0].message.content)

# Used for: Accelerating SOC analyst workflow and decision-making
# summarize_alert("4624 login from 5.6.7.8, followed by execution of rundll32.exe and PowerShell iex")
