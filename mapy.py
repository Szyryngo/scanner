import folium
import webbrowser

def show_map(ip, lat, lon):
    m = folium.Map(location=[lat, lon], zoom_start=6)
    folium.Marker([lat, lon], popup=f"IP: {ip}").add_to(m)
    m.save("geo_map.html")
    webbrowser.open("geo_map.html")
