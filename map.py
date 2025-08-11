import folium
import webbrowser
import os

def show_map(ip, lat=52.2297, lon=21.0122):
    try:
        map_obj = folium.Map(location=[lat, lon], zoom_start=10)
        folium.Marker([lat, lon], popup=f"IP: {ip}", icon=folium.Icon(color="red")).add_to(map_obj)

        map_path = os.path.abspath("ip_map.html")
        map_obj.save(map_path)
        webbrowser.open(f"file://{map_path}")
    except Exception as e:
        print(f"❌ Błąd mapy: {e}")
