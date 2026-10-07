import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

class AnomalyDetectorML:
    def __init__(self, contamination=0.05):
        # contamination = expected percentage of anomalous activity
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.is_trained = False

    def extract_features(self, df):
        """Converts raw logs into quantitative behavioral metrics per IP."""
        features = df.groupby('ip').agg(
            total_attempts=('status', 'count'),
            failed_attempts=('status', lambda x: (x == 'Failed').sum()),
            unique_users=('user', 'nunique')
        ).reset_index()
        
        features['failure_rate'] = features['failed_attempts'] / features['total_attempts']
        return features

    def train(self, historical_df):
        features = self.extract_features(historical_df)
        X = features[['total_attempts', 'failed_attempts', 'unique_users', 'failure_rate']]
        self.model.fit(X)
        self.is_trained = True

    def predict(self, feature_vector):
        if not self.is_trained:
            return 1 # Default normal
        # Returns -1 for anomaly, 1 for normal
        return self.model.predict(feature_vector)[0]
