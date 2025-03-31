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
WIDTH = 80

#URL BASE
URL_THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
URL_ALIENVAULT = "https://otx.alienvault.com/api/v1/indicators/file"

def threatfox(HASH):
    AUTH_API = "API_THREATFOX"
    API_TOKEN = load_auth(AUTH_API)

    headers = {
    'User-Agent': USER_AGENT,
    'Auth-Key': API_TOKEN,
    }
    payload = {
    'query': "search_ioc",
    'search_term': HASH,
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
                    f" - No indicators associated with the HASH are found\n"
                )

def alienvault(HASH):
    AUTH_API = "API_URLSCANIO"
    API_TOKEN = load_auth(AUTH_API)

    headers = {
    'User-Agent': USER_AGENT,
    'X-OTX-API-KEY': API_TOKEN,
    }

    try:
        response = requests.get(f"{URL_ALIENVAULT}/{HASH}/general", headers=headers, timeout=5)
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

def analyze_hash(HASH):
    print("\n" + "=" * WIDTH)
    print(f"{HASH}".center(WIDTH))
    print("=" * WIDTH + "\n")
    threatfox(HASH)
    alienvault(HASH)

def analyze_hash_file(HASH_FILE):
    with open(HASH_FILE, "r", encoding="utf-8") as f:
        for line in f:
            HASH = line.strip()
            if HASH:
                analyze_hash(HASH)

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