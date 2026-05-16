"""
Threat Prediction Engine for SAERA
Utilizes Machine Learning to predict the likelihood of critical exposure
based on observed environmental patterns.
"""
import os
import pickle
import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

class ThreatPredictor:
    def __init__(self):
        self.model_path = os.path.join(os.path.dirname(__file__), 'threat_model.pkl')
        self.model = self._load_model()
        
    def _load_model(self):
        if SKLEARN_AVAILABLE and os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    return pickle.load(f)
            except:
                return None
        return None
        
    def train_initial_model(self):
        """Train a baseline model for academic demonstration"""
        if not SKLEARN_AVAILABLE:
            return False
            
        # Features: [num_open_ports, num_services, has_critical_vulns, avg_risk_score]
        # X: Features, y: Is highly vulnerable (0/1)
        X = np.array([
            [1, 1, 0, 1.2],
            [2, 1, 0, 2.5],
            [10, 5, 1, 8.5],
            [20, 8, 1, 9.5],
            [5, 4, 0, 4.5],
            [8, 6, 1, 7.8],
            [1, 1, 1, 9.0],
            [3, 3, 0, 3.5],
            [15, 10, 1, 8.9],
            [4, 2, 0, 2.1],
        ])
        y = np.array([0, 0, 1, 1, 0, 1, 1, 0, 1, 0])
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X, y)
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        return True
            
    def predict_risk_probability(self, num_ports, num_services, has_critical, avg_risk):
        """
        Predict the probability (0-100%) of the target having 
        an immediate critical exposure risk.
        """
        if not SKLEARN_AVAILABLE:
            # Fallback to simple heuristic if sklearn is missing
            heuristic = (avg_risk * 7) + (num_ports * 2)
            if has_critical: heuristic += 30
            return round(min(heuristic, 99.9), 1)
            
        if not self.model:
            self.train_initial_model()
            
        if not self.model:
            return 0.0
            
        features = np.array([[num_ports, num_services, 1 if has_critical else 0, avg_risk]])
        try:
            # Get probability of class 1 (High Risk)
            probability = self.model.predict_proba(features)[0][1]
            return round(probability * 100, 1)
        except:
            return 0.0

# Singleton instance
predictor = ThreatPredictor()
