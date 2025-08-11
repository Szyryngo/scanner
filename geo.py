# geo.py

import requests

def get_geo(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,lat,lon", timeout=3)
        data = response.json()
        return {
            "country": data.get("country", "Nieznany"),
            "city": data.get("city", "Nieznane"),
            "lat": data.get("lat", "0.0"),
            "lon": data.get("lon", "0.0")
        }
    except Exception as e:
        print(f"[❌] Błąd geolokalizacji: {e}")
        return {
            "country": "Błąd",
            "city": "Błąd",
            "lat": "0.0",
            "lon": "0.0"
        }
