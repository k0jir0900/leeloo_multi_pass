import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), 'files'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts_main'))

import json
import time
import requests
import pyfiglet
import pycountry
import bye_message


# GENERAL
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
SECRET_FILE = "secret.json"
OUPUT_LIMIT = 5

#URL BASE
URL_URLSCAN = "https://urlscan.io/api/v1/scan/"
URL_THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
URL_ALIENVAULT = "https://otx.alienvault.com/api/v1/indicators/url"

def urlscan(URL):
    AUTH_API = "API_URLSCANIO"
    API_TOKEN = load_auth(AUTH_API)

    headers = {
    'User-Agent': USER_AGENT,
    'Content-Type': 'application/json',
    'API-Key': API_TOKEN
    }
    headers_result = {
    'User-Agent': USER_AGENT,
    'Content-Type': 'application/json',
    }
    payload = {
    'url': URL,
    'visibility': "public"
    }

    try:
        response = requests.post(f"{URL_URLSCAN}", headers=headers, json=payload, timeout=5)
    except Exception as e:
        print("-"*80)
        print(e)
        print("-"*80)
    else:
        if response.status_code == 200:
            j_data = response.json()
            message = j_data["message"]
            result = j_data["api"]

            print(
                    f"🔗 URLSCAN\n"
                    f" - Status: {message}\n"
                    f" - Result: {result}"
                )
            
            print(f" - Waiting for results...")
            while True:
                time.sleep(5)
                response_result = requests.get(result, headers=headers_result)
                r_data = response_result.json()

                if response_result.status_code == 200:
                    jr_data = response_result.json()
                    apexdomain = jr_data["task"]["apexDomain"]
                    domain_url = jr_data["task"]["url"]
                    reportURL = jr_data["task"]["reportURL"]
                    screenshotURL = jr_data["task"]["screenshotURL"]
                    verdicts = jr_data["verdicts"]["overall"]["malicious"]

                    print(
                    f"\n🔗 URLSCAN - Result\n"
                    f" - Domain: {apexdomain}\n"
                    f" - URL: {domain_url}\n"
                    f" - Report URL: {reportURL}\n"
                    f" - Report screenshot: {screenshotURL}\n"
                    f" - Malware veredict: {verdicts}\n"
                )
                    break
                        
                else:
                    time.sleep(5)
        else:
            j_data = response.json()
            print(f"Error: {j_data}")

def threatfox(URL):
    AUTH_API = "API_THREATFOX"
    API_TOKEN = load_auth(AUTH_API)

    headers = {
    'User-Agent': USER_AGENT,
    'Auth-Key': API_TOKEN,
    }
    payload = {
    'query': "search_ioc",
    'search_term': URL,
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
                    f" - No indicators associated with the URL are found\n"
                )

def alienvault(URL):
    AUTH_API = "API_URLSCANIO"
    API_TOKEN = load_auth(AUTH_API)

    headers = {
    'User-Agent': USER_AGENT,
    'X-OTX-API-KEY': API_TOKEN,
    }

    try:
        response = requests.get(f"{URL_ALIENVAULT}/{URL}/general", headers=headers, timeout=5)
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

def analyze_url(URL):
    temp_width = 80
    print("\n" + "=" * temp_width)
    print(f"{URL}".center(temp_width))
    print("=" * temp_width + "\n")
    urlscan(URL)
    threatfox(URL)
    alienvault(URL)

def analyze_url_file(URL_FILE):

    with open(URL_FILE, "r", encoding="utf-8") as f:
        for line in f:
            URL = line.strip()
            if URL:
                analyze_url(URL)

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