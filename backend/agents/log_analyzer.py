"""
Log Analyzer Agent
Detects anomalies in network traffic using Isolation Forest
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple
import joblib
from pathlib import Path
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.preprocessor import LogPreprocessor


class LogAnalyzerAgent:
    """
    AI Agent for anomaly detection in security logs
    Uses unsupervised learning to identify suspicious patterns
    """
    
    def __init__(self, contamination: float = 0.05):
        """
        Initialize the Log Analyzer Agent
        
        Args:
            contamination: Expected proportion of anomalies (default 5%)
        """
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.preprocessor = LogPreprocessor()
        self.is_trained = False
        self.feature_names = []
        
    def extract_ml_features(self, processed_logs: List[Dict]) -> pd.DataFrame:
        """
        Extract numerical features for ML from processed logs
        
        Args:
            processed_logs: List of preprocessed log dictionaries
            
        Returns:
            DataFrame with numerical features
        """
        features_list = []
        
        for log in processed_logs:
            feature_dict = {
                # Temporal features
                'hour_of_day': log['features']['hour_of_day'],
                'day_of_week': log['features']['day_of_week'],
                'is_off_hours': int(log['features']['is_off_hours']),
                'is_weekend': int(log['features']['is_weekend']),
                
                # Network features
                'bytes_sent': log['bytes_sent'],
                'bytes_received': log['bytes_received'],
                'bytes_ratio': log['features']['bytes_ratio'],
                'data_volume': log['features']['data_transfer_volume'],
                'duration': log['duration'],
                'port': log['port'],
                
                # Behavioral features
                'high_port': int(log['features']['high_port']),
                'failed_action': int(log['features']['failed_action']),
                'is_https': int(log['features']['is_https']),
                'long_duration': int(log['features']['long_duration']),
            }
            features_list.append(feature_dict)
        
        df = pd.DataFrame(features_list)
        self.feature_names = df.columns.tolist()
        return df
    
    def train(self, raw_logs: List[Dict]) -> Dict:
        """
        Train the anomaly detection model
        
        Args:
            raw_logs: List of raw log dictionaries
            
        Returns:
            Training statistics
        """
        processed_logs = self.preprocessor.process_batch(raw_logs)
        features_df = self.extract_ml_features(processed_logs)
        features_scaled = self.scaler.fit_transform(features_df)
        self.model.fit(features_scaled)
        self.is_trained = True
        
        stats = {
            "total_logs": len(raw_logs),
            "features_used": len(self.feature_names),
            "model": "Isolation Forest",
            "contamination": self.model.contamination
        }
        return stats
    
    def detect_anomalies(self, raw_logs: List[Dict]) -> Tuple[List[Dict], pd.DataFrame]:
        """
        Detect anomalies in logs using both ML and rule-based detection
    
        Args:
            raw_logs: List of raw log dictionaries
        
        Returns:
            Tuple of (anomaly_logs, full_results_df)
        """
        if not self.is_trained:
            raise Exception(" Model not trained! Call train() first.")
    
        # Process logs
        processed_logs = self.preprocessor.process_batch(raw_logs)
        features_df = self.extract_ml_features(processed_logs)
        features_scaled = self.scaler.transform(features_df)
    
        # Predict anomalies using ML
        predictions = self.model.predict(features_scaled)
        anomaly_scores = self.model.score_samples(features_scaled)
    
        # Add results to dataframe
        results_df = features_df.copy()
        results_df['is_anomaly'] = predictions == -1
        results_df['anomaly_score'] = anomaly_scores
    
        # Apply rule-based checks (override ML for obvious cases)
        for idx, processed_log in enumerate(processed_logs):
            if self._check_rule_based_anomalies(processed_log):
                results_df.at[idx, 'is_anomaly'] = True
                # Set a very negative score for rule-based detections
                if results_df.at[idx, 'anomaly_score'] > -0.5:
                    results_df.at[idx, 'anomaly_score'] = -0.8
    
        results_df['severity'] = results_df['anomaly_score'].apply(self._calculate_severity)
    
        # Extract anomalies with original log data
        anomalies = []
        for idx, row in results_df[results_df['is_anomaly']].iterrows():
            anomaly_entry = {
                **processed_logs[idx],
                'anomaly_score': float(row['anomaly_score']),
                'severity': row['severity'],
                'detected_at': pd.Timestamp.now().isoformat(),
                'detection_method': 'rule-based' if self._check_rule_based_anomalies(processed_logs[idx]) else 'ml-based'
            }
            anomalies.append(anomaly_entry)
    
        return anomalies, results_df
    
    def _calculate_severity(self, score: float) -> str:
        """
        Calculate threat severity based on anomaly score
        
        Args:
            score: Anomaly score (more negative = more anomalous)
            
        Returns:
            Severity level: "low", "medium", "high", "critical"
        """
        if score < -0.3:
            return "critical"
        elif score < -0.2:
            return "high"
        elif score < -0.1:
            return "medium"
        else:
            return "low"
    
    def get_top_anomalies(self, anomalies: List[Dict], top_n: int = 10) -> List[Dict]:
        """Get the top N most anomalous logs"""
        sorted_anomalies = sorted(
            anomalies,
            key=lambda x: x['anomaly_score']
        )
        return sorted_anomalies[:top_n]
    
    def save_model(self, path: str = "models/log_analyzer.pkl"):
        """Save trained model to disk"""
        if not self.is_trained:
            raise Exception("Cannot save untrained model")
        
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }, path)
        print(f" Model saved to {path}")
    
    def load_model(self, path: str = "models/log_analyzer.pkl"):
        """Load trained model from disk"""
        data = joblib.load(path)
        self.model = data['model']
        self.scaler = data['scaler']
        self.feature_names = data['feature_names']
        self.is_trained = True
        print(f" Model loaded from {path}")

    def train_on_benign_only(self, raw_logs: List[Dict], label_column: str = ' Label') -> Dict:
        """
        Train on benign traffic only, so attacks become anomalies
    
        Args:
            raw_logs: List of raw log dictionaries
            label_column: Name of the label column in CICIDS data (note the space!)
        
        Returns:
            Training statistics
        """
        print(" Filtering for BENIGN traffic only...")
    
        # Filter for benign logs only
        benign_logs = [
            log for log in raw_logs 
            if str(log.get(label_column, '')).strip().upper() == 'BENIGN'
        ]
    
        if not benign_logs:
            # Try without space
            label_column = 'Label'
            benign_logs = [
                log for log in raw_logs 
                if str(log.get(label_column, '')).strip().upper() == 'BENIGN'
            ]
    
        if not benign_logs:
            print(f" Available columns: {list(raw_logs[0].keys())[:10]}")
            raise Exception("No benign logs found! Check label column name.")
    
        print(f" Found {len(benign_logs)} benign logs out of {len(raw_logs)} total")
        print(f" {len(raw_logs) - len(benign_logs)} attack logs will be treated as anomalies")
    
        # Train on benign traffic
        return self.train(benign_logs)
    
    def _check_rule_based_anomalies(self, processed_log: Dict) -> bool:
        """
        Rule-based checks for obvious anomalies that should always trigger
        Returns True if this log should be flagged regardless of ML model
        """
        # Extreme data transfer (> 50 MB in one direction)
        if processed_log.get('bytes_sent', 0) > 50_000_000:
            return True
    
        if processed_log.get('bytes_received', 0) > 50_000_000:
            return True
    
        # Extreme ratio (1000:1 or more)
        bytes_sent = processed_log.get('bytes_sent', 0)
        bytes_received = processed_log.get('bytes_received', 1)  # Avoid division by zero
    
        if bytes_sent > 0 and bytes_received > 0:
            ratio = max(bytes_sent / bytes_received, bytes_received / bytes_sent)
            if ratio > 1000:
                return True
    
        # Extremely fast large transfer (> 10MB in < 0.01 seconds)
        duration = processed_log.get('duration', 1.0)
        total_bytes = bytes_sent + bytes_received
        if duration < 0.01 and total_bytes > 10_000_000:
            return True
    
        # Off-hours + failed action
        features = processed_log.get('features', {})
        if features.get('is_off_hours') and features.get('failed_action'):
            return True
    
        return False

def main():
    """Test the Log Analyzer Agent"""
    print("  AutoSec AI - Log Analyzer Agent Test")
    print("=" * 60)
    
    # Initialize agent
    agent = LogAnalyzerAgent(contamination=0.05)
    
    # Load CICIDS data (limit to first 10000 rows for speed)
    print("\n Loading CICIDS dataset...")
    preprocessor = LogPreprocessor()
    
    # Load one CSV file for testing
    import pandas as pd
    csv_path = "../../data/raw/cicids/Friday-WorkingHours-Morning-pcap_ISCX.csv"
    
    try:
        df = pd.read_csv(csv_path, nrows=10000)
        raw_logs = df.to_dict('records')
        print(f" Loaded {len(raw_logs)} logs")
    except FileNotFoundError:
        print(f" File not found: {csv_path}")
        print("Please ensure CICIDS data is in data/raw/cicids/")
        return
    
    # Train the agent
    print("\n Training anomaly detection model...")
    stats = agent.train(raw_logs)
    print(f"   Stats: {stats}")
    
    # Detect anomalies
    print("\n Detecting anomalies...")
    anomalies, results_df = agent.detect_anomalies(raw_logs)
    
    print(f"\n Results:")
    print(f"   Total logs analyzed: {len(raw_logs)}")
    print(f"   Anomalies detected: {len(anomalies)}")
    print(f"   Detection rate: {len(anomalies)/len(raw_logs)*100:.2f}%")
    
    # Show severity distribution
    severity_counts = results_df[results_df['is_anomaly']]['severity'].value_counts()
    print(f"\n  Severity Distribution:")
    for severity, count in severity_counts.items():
        print(f"   {severity.upper()}: {count}")
    
    # Show top 5 most anomalous
    top_anomalies = agent.get_top_anomalies(anomalies, top_n=5)
    print(f"\n Top 5 Most Anomalous Events:")
    for i, anomaly in enumerate(top_anomalies, 1):
        print(f"\n   #{i} - Severity: {anomaly['severity'].upper()}")
        print(f"       Score: {anomaly['anomaly_score']:.4f}")
        print(f"       Action: {anomaly['action']}")
        print(f"       Source IP: {anomaly['source_ip']}")
        print(f"       Bytes Sent: {anomaly['bytes_sent']}")
    
    # Save model
    agent.save_model()
    print("\n Agent test complete!")
    


if __name__ == "__main__":
    main()