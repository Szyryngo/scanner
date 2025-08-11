# netsentinel_ai/anomalies.py
import math
from statistics import median
try:
    from sklearn.ensemble import IsolationForest
except Exception:
    IsolationForest = None

class AnomalyEngine:
    def __init__(self, active_traffic, sensitivity=0.15):
        self.active = active_traffic
        self.sensitivity = max(0.01, min(0.5, sensitivity))  # udział anomalii

    def set_sensitivity(self, val):
        self.sensitivity = max(0.01, min(0.5, float(val)))

    def _features(self, snap):
        feats = []
        for d in snap:
            feats.append({
                "ip": d["ip"],
                "packets": d["packets"],
                "bytes": d["bytes"],
                "uniq_ports": len(d.get("ports", []))
            })
        return feats

    def _zscore_scores(self, feats):
        # prosty skoring bez sklearn
        vals = {}
        for k in ["packets", "bytes", "uniq_ports"]:
            xs = [f[k] for f in feats]
            if not xs:
                vals[k] = (0, 1)
                continue
            m = median(xs)
            mad = median([abs(x - m) for x in xs]) or 1.0
            vals[k] = (m, mad)
        res = []
        for f in feats:
            s = 0.0
            for k, w in [("packets", 0.4), ("bytes", 0.4), ("uniq_ports", 0.2)]:
                m, mad = vals[k]
                s += w * (abs(f[k] - m) / mad)
            res.append({"ip": f["ip"], "score": s, **f})
        res.sort(key=lambda x: x["score"], reverse=True)
        # przytnij top wg czułości
        n = max(1, int(len(res) * self.sensitivity))
        return res[:n]

    def get_results(self):
        snap = self.active.get_snapshot()
        feats = self._features(snap)
        if not feats:
            return []
        if IsolationForest and len(feats) >= 8:
            import numpy as np
            X = np.array([[f["packets"], f["bytes"], f["uniq_ports"]] for f in feats], dtype=float)
            model = IsolationForest(n_estimators=100, contamination=self.sensitivity, random_state=42)
            model.fit(X)
            scores = -model.score_samples(X)  # większe = bardziej anomalia
            res = []
            for f, sc in zip(feats, scores):
                res.append({"ip": f["ip"], "score": float(sc), **f})
            res.sort(key=lambda x: x["score"], reverse=True)
            n = max(1, int(len(res) * self.sensitivity))
            return res[:n]
        else:
            return self._zscore_scores(feats)