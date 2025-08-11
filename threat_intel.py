import requests
import logging

# 🔑 Wstaw swój klucz API tutaj
API_KEY = "63d04bb48f5fd3d184f1d742071f20b604d726754cd8083485fc1662a9d16705584c539e411f469d"

# 📊 Próg zgłoszeń, powyżej którego IP uznawane jest za złośliwe
THREAT_THRESHOLD = 5

def check_ip_threat(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()["data"]
            abuse_count = data.get("totalReports", 0)
            is_malicious = abuse_count >= THREAT_THRESHOLD
            return {
                "ip": ip,
                "malicious": is_malicious,
                "reports": abuse_count,
                "country": data.get("countryName", "Unknown"),
                "usage": data.get("usageType", "Unknown")
            }
        elif response.status_code == 429:
            logging.warning("AbuseIPDB API limit exceeded (429)")
            return {}
        else:
            logging.warning(f"AbuseIPDB API returned status {response.status_code}")
            return {}
    except requests.RequestException as e:
        logging.exception("Threat API request failed")
        return {}

