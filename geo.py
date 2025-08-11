import requests
import logging

logging.basicConfig(level=logging.INFO)

def get_geo_info(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            logging.warning(f"Geo API returned status {response.status_code}")
            return {}
    except requests.RequestException as e:
        logging.exception("Geo API request failed")
        return {}
