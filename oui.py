import requests
import logging

logging.basicConfig(level=logging.INFO)

def get_vendor(mac):
    try:
        prefix = mac.upper().replace(":", "")[:6]
        response = requests.get(f"https://api.macvendors.com/{prefix}", timeout=5)
        if response.status_code == 200:
            return response.text
        else:
            logging.warning(f"OUI API returned status {response.status_code}")
            return "Unknown"
    except requests.RequestException as e:
        logging.exception("OUI API request failed")
        return "Unknown"
