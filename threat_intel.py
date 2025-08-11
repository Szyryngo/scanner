import requests
import logging

logging.basicConfig(level=logging.INFO)

def check_ip_threat(ip):
    try:
        response = requests.get(f"https://threatapi.example.com/check?ip={ip}", timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            logging.warning(f"Threat API returned status {response.status_code}")
            return {}
    except requests.RequestException as e:
        logging.exception("Threat API request failed")
        return {}
