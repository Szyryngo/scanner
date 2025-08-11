import matplotlib.pyplot as plt

def show_anomaly_chart(stats):
    labels = ["Pakiety", "Zagrożenia", "Anomalie"]
    values = [stats.get("packets", 0), stats.get("threats", 0), stats.get("alerts", 0)]

    plt.figure(figsize=(6, 4))
    plt.bar(labels, values, color=["blue", "red", "orange"])
    plt.title("Statystyki sieciowe")
    plt.ylabel("Liczba")
    plt.tight_layout()
    plt.show()
