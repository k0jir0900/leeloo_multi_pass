import os
import json
import shutil
import requests
import pyfiglet
import argparse
import pycountry

# GENERAL
BANNER = "Leeloo Multi Pass"
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

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner_text = pyfiglet.figlet_format(BANNER)
    print(banner_text)

def analyze_ip(IP):
    width = shutil.get_terminal_size((80, 20)).columns
    print("#" * width)
    print(f"⭐ {IP} ⭐".center(width))
    print("#" * width + "\n")
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

    response = requests.get(f"{URL_IPINFO}/{IP}?token={API_TOKEN}", headers=headers)
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

    response = requests.get(f"{URL_ABUSEIPDB}{IP}", headers=headers, params=params)
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

    response = requests.post(f"{URL_THREATFOX}", headers=headers, json=payload)
    if response.status_code == 200:
        j_data = response.json()
        if j_data.get("query_status") == "ok":
            print(
                f"🦊 Threat Fox\n"
            )
        else:
            print(
                f"🦊 Threat Fox\n"
                f" - No se encuentran indicadores asociados a la IP\n"
            )

def alienvault(IP):
    AUTH_API = "API_ALIENVAULT"
    API_TOKEN = load_auth(AUTH_API)

    headers = {
    'User-Agent': USER_AGENT,
    'X-OTX-API-KEY': API_TOKEN,
    }

    response = requests.get(f"{URL_ALIENVAULT}/{IP}/general", headers=headers)
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
        print(f"⚠️ Archivo no encontrado: {ABUSEIPDB_CODES}")
        return category_ids
    except Exception as e:
        print(f"⚠️ Error procesando categorías: {e}")
        return category_ids


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Consulta información sobre una IP en múltiples fuentes.")
    parser.add_argument("-i", "--ip", help="IP individual a consultar")
    parser.add_argument("-f", "--file", help="Archivo con IPs, una por línea")

    args = parser.parse_args()

    banner()

    if args.ip:
        analyze_ip(args.ip)

    elif args.file:
        if os.path.exists(args.file):
            with open(args.file, "r", encoding="utf-8") as f:
                for line in f:
                    IP = line.strip()
                    if IP:
                        analyze_ip(IP)
        else:
            print(f"⚠️  El archivo no existe.\n")
    else:
        print(f"⚠️  Debes proporcionar una IP con -i o un archivo con -f.\n")