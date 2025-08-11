import matplotlib.pyplot as plt

def show_anomaly_chart(stats):
    try:
        labels = list(stats.keys())
        values = list(stats.values())

        plt.figure(figsize=(8, 5))
        bars = plt.bar(labels, values, color=["blue", "orange", "red"])
        plt.title("📈 Statystyki ruchu sieciowego")
        plt.ylabel("Liczba zdarzeń")

        for bar in bars:
            yval = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2.0, yval + 1, int(yval), ha='center', va='bottom')

        plt.tight_layout()
        plt.show()
    except Exception as e:
        print(f"❌ Błąd wykresu: {e}")
