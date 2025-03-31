import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), 'files'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts_main'))

import json
import requests
import pyfiglet
import pycountry
import bye_message

# GENERAL
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
SECRET_FILE = "secret.json"
OUPUT_LIMIT = 5

#URL BASE
URL_IPINFO = "https://ipinfo.io"
URL_ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check?ipAddress="
URL_THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
URL_ALIENVAULT = "https://otx.alienvault.com/api/v1/indicators/IPv4"

#EXTRA DATA
ABUSEIPDB_CODES = "files/abuseipdb_codes.json"

def analyze_ip_file(FILE):

    with open(FILE, "r", encoding="utf-8") as f:
        for line in f:
            IP = line.strip()
            if IP:
                analyze_ip(IP)

def analyze_ip(IP):
    temp_width = 80
    print("\n" + "=" * temp_width)
    print(f"{IP}".center(temp_width))
    print("=" * temp_width + "\n")
    ipinfo(IP)
    abuseipdb(IP)
    threatfox(IP)
    alienvault(IP)

def ipinfo(IP):
    AUTH_API = "API_IPINFO"
    API_TOKEN = load_auth(AUTH_API)

    headers = {
    'User-Agent': USER_AGENT,
    'Accept': 'application/json',
    }

    try:
        response = requests.get(f"{URL_IPINFO}/{IP}?token={API_TOKEN}", headers=headers, timeout=5)
    except Exception as e:
        print("-"*80)
        print(e)
        print("-"*80)
    else:
        if response.status_code == 200:
            j_data = response.json()
            country = country_name(j_data["country"])
            region= j_data["region"]
            city = j_data["city"]
            asn = j_data["org"]

            print(
                f"🌐 IP Info\n"
                f" - Country: {country}\n"
                f" - Region: {region}\n"
                f" - City: {city}\n"
                f" - ASN: {asn}\n"
            )

def abuseipdb(IP):
    AUTH_API = "API_ABUSEIPDB"
    API_TOKEN = load_auth(AUTH_API)

    headers = {
    'User-Agent': USER_AGENT,
    'Key': API_TOKEN,
    'Accept': 'application/json',
    }
    params = {
        'maxAgeInDays': 90,
        'verbose': ''
    }

    try:
        response = requests.get(f"{URL_ABUSEIPDB}{IP}", headers=headers, params=params, timeout=5)
    except Exception as e:
        print("-"*80)
        print(e)
        print("-"*80)
    else:
        if response.status_code == 200:
            j_data = response.json()
            data = j_data.get("data", {})
            total_reports = data.get("totalReports")

            if total_reports == 0:

                score = j_data["data"]["abuseConfidenceScore"]
                tor = j_data["data"]["isTor"]
                report = j_data["data"]["totalReports"]
                last_report = j_data["data"]["lastReportedAt"]

                print(
                    f"🔮 AbuseIP DB\n"
                    f" - Abuse Score: {score}\n"
                    f" - TOR: {tor}\n"
                    f" - Reports: {report}\n"
                    f" - Last Report: {last_report}\n"
                )

            else:
                score = j_data["data"]["abuseConfidenceScore"]
                tor = j_data["data"]["isTor"]
                report = j_data["data"]["totalReports"]
                last_report = j_data["data"]["lastReportedAt"]

                lines = [
                    f"🔮 AbuseIP DB\n"
                    f" - Abuse Score: {score}\n"
                    f" - TOR: {tor}\n"
                    f" - Reports: {report}\n"
                    f" - Last Report: {last_report}\n"
                    f" - Report Details ({OUPUT_LIMIT}):\n"
                ]

                REPORTS = j_data.get("data", {}).get("reports", [])
                for report in REPORTS[:OUPUT_LIMIT]:
                    comment = report.get("comment")
                    reportedat = report.get("reportedAt")
                    category_id = report.get("categories", [])
                    categories = abuseipdb_codes(category_id)

                    lines.append(
                        f"  - Comment: {comment}\n"
                        f"  - Reported: {reportedat}\n"
                        f"  - Reported: {categories}\n"
                    )
                
                print("\n".join(lines))

def threatfox(IP):
    AUTH_API = "API_THREATFOX"
    API_TOKEN = load_auth(AUTH_API)

    headers = {
    'User-Agent': USER_AGENT,
    'Auth-Key': API_TOKEN,
    }
    payload = {
    'query': "search_ioc",
    'search_term': IP,
    'exact_match': "false"
    }

    try:
        response = requests.post(f"{URL_THREATFOX}", headers=headers, json=payload, timeout=5)
    except Exception as e:
        print("-"*80)
        print(e)
        print("-"*80)
    else:
        if response.status_code == 200:
            j_data = response.json()
            if j_data.get("query_status") == "ok":
                for entry in j_data["data"]:
                    ioc = entry["ioc"]
                    threat_type = entry["threat_type"]
                    malware_printable = entry["malware_printable"]
                    confidence_level = entry["confidence_level"]
                    first_seen = entry["first_seen"]
                    last_seen = entry["last_seen"]
                    malware_malpedia = entry["malware_malpedia"]

                    print(
                        f"🦊 Threat Fox\n"
                        f" - URL: {ioc}\n"
                        f" - Threat type: {threat_type}\n"
                        f" - Malware: {malware_printable}\n"
                        f" - Confidence: {confidence_level}\n"
                        f" - First seen: {first_seen}\n"
                        f" - Last seen: {last_seen}\n"
                        f" - Malpedia: {malware_malpedia}\n"
                    )
            else:
                print(
                    f"🦊 Threat Fox\n"
                    f" - No indicators associated with the IP are found\n"
                )

def alienvault(IP):
    AUTH_API = "API_ALIENVAULT"
    API_TOKEN = load_auth(AUTH_API)

    headers = {
    'User-Agent': USER_AGENT,
    'X-OTX-API-KEY': API_TOKEN,
    }

    try:
        response = requests.get(f"{URL_ALIENVAULT}/{IP}/general", headers=headers, timeout=5)
    except Exception as e:
        print("-"*80)
        print(e)
        print("-"*80)
    else:    
        if response.status_code == 200:
            j_data = response.json()
            if j_data.get("pulse_info", {}).get("count") == 0:
                pulse_count = j_data["pulse_info"]["count"]

                print(
                    f"👽 Alienvault\n"
                    f" - Pulse Count: {pulse_count}\n"
                )

            else:
                pulse_count = j_data["pulse_info"]["count"]

                lines = [
                    "👽 Alienvault\n"
                    f" - Pulse Count: {pulse_count}\n"
                ]

                PULSE_INFO = j_data.get("pulse_info", {}).get("pulses", [])
                for pulse in PULSE_INFO[:OUPUT_LIMIT]:
                    name = pulse.get("name")
                    created = pulse.get("created")
                    modified = pulse.get("modified")
                    tags = pulse.get("tags")


                    lines.append(
                        f" - Pulse Name: {name}\n"
                        f"  - Created: {created}\n"
                        f"  - Modified: {modified}\n"
                        f"  - Tags: {tags}\n"
                    )
                    
                print("\n".join(lines) + "\n")

def load_auth(AUTH_API):
    try:
        with open(SECRET_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
            auth_config = config.get(f"{AUTH_API}", {})
            if auth_config == "-":
                print(f"The {AUTH_API} setting was not found\n")
            return auth_config
    except Exception as e:
        raise Exception(f"{str(e)}")
    
def country_name(code):
    try:
        country = pycountry.countries.get(alpha_2=code.upper())
        return country.name if country else f"Unknown ({code})"
    except Exception as e:
        return f"Error: {str(e)}"
    
def abuseipdb_codes(category_ids):
    try:
        with open(ABUSEIPDB_CODES, "r", encoding="utf-8") as f:
            codes = json.load(f)
        
        id_to_category = {item["id"]: item["category"] for item in codes}
        return [id_to_category.get(cat_id, f"Unknown({cat_id})") for cat_id in category_ids]
    
    except FileNotFoundError:
        print(f"⚠️ File not found: {ABUSEIPDB_CODES}")
        return category_ids
    except Exception as e:
        print(f"⚠️ Error: {e}")
        return category_ids   