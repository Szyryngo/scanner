import unittest
from ai import train_model, predict_anomaly
import os
import pandas as pd

class TestAI(unittest.TestCase):

    def setUp(self):
        self.data_path = "test_data.csv"
        df = pd.DataFrame({
            "packet_size": [100, 2000, 80],
            "geo_distance": [0.0, 0.0, 0.0],
            "threat_score": [0, 1, 0],
            "time_delta": [0.1, 0.4, 0.2]
        })
        df.to_csv(self.data_path, index=False)

    def test_train_model(self):
        train_model(self.data_path, "test_model.pkl")
        self.assertTrue(os.path.exists("test_model.pkl"))

    def test_predict_anomaly(self):
        train_model(self.data_path, "test_model.pkl")
        result = predict_anomaly([2000, 0.0, 1, 0.4], "test_model.pkl")
        self.assertIsInstance(result, bool)

    def tearDown(self):
        os.remove(self.data_path)
        if os.path.exists("test_model.pkl"):
            os.remove("test_model.pkl")

if __name__ == "__main__":
    unittest.main()
