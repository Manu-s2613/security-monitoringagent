"""
AI-Based Cloud Security Monitoring - Anomaly Detection Module
Uses Isolation Forest for unsupervised anomaly detection
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
import os
warnings.filterwarnings('ignore')



# ===============================
# SAFE DATASET PATH HANDLING
# ===============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "..", "dataset")
CLOUD_LOGS_PATH = os.path.join(DATASET_DIR, "cloud_logs.csv")
THREATS_PATH = os.path.join(DATASET_DIR, "detected_threats.csv")

os.makedirs(DATASET_DIR, exist_ok=True)



class CloudSecurityAnomalyDetector:
    """
    Machine Learning based anomaly detection system for cloud security monitoring.
    Uses Isolation Forest algorithm for unsupervised anomaly detection.
    """
    
    def __init__(self, contamination=0.15):
        """
        Initialize the anomaly detector
        
        Args:
            contamination: Expected proportion of anomalies (default: 15%)
        """
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
    
    def train(self, data):
        """
        Train the Isolation Forest model on cloud activity data
        
        Args:
            data: DataFrame with features for training
        """
        # Select relevant features for anomaly detection
        features = ['login_count', 'cpu_usage', 'network_in', 'network_out']
        X = data[features].values
        
        # Normalize features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.model.fit(X_scaled)
        self.is_trained = True
        
        print(f"✓ Model trained on {len(data)} records")
        return self
    
    def detect_anomalies(self, data):
        """
        Detect anomalies in cloud activity data
        
        Args:
            data: DataFrame with cloud activity logs
            
        Returns:
            DataFrame with anomaly predictions and scores
        """
        if not self.is_trained:
            raise Exception("Model not trained. Call train() first.")
        
        # Select features
        features = ['login_count', 'cpu_usage', 'network_in', 'network_out']
        X = data[features].values
        
        # Normalize
        X_scaled = self.scaler.transform(X)
        
        # Predict anomalies (-1 = anomaly, 1 = normal)
        predictions = self.model.predict(X_scaled)
        
        # Get anomaly scores (lower = more anomalous)
        scores = self.model.score_samples(X_scaled)
        
        # Add predictions to dataframe
        result = data.copy()
        result['is_anomaly'] = predictions == -1
        result['anomaly_score'] = scores
        
        return result
    
    def classify_attack_type(self, row):
        """
        Rule-based attack classification based on behavioral patterns
        
        Args:
            row: Single row of activity data
            
        Returns:
            Attack type string
        """
        cpu = row['cpu_usage']
        net_in = row['network_in']
        net_out = row['network_out']
        logins = row['login_count']
        
        # Rule-based attack classification
        if net_out > 800 and cpu > 85:
            return "Data Breach"
        elif logins > 15 and cpu > 80:
            return "Account Hijacking"
        elif cpu > 95 and net_in > 600:
            return "Malware Injection"
        elif net_in > 700 and net_out > 700:
            return "Insecure APIs"
        elif logins > 20:
            return "Phishing Impact"
        elif net_in > 900 or net_out > 900:
            return "DoS / DDoS"
        elif cpu > 90 and logins < 5:
            return "Insider Threats"
        elif logins > 10 and cpu > 75:
            return "Shared Vulnerabilities"
        elif cpu < 20 and net_out > 500:
            return "Cloud Misconfiguration"
        else:
            return "Unknown Threat"
    
    def calculate_risk_level(self, row):
        """
        Calculate risk level based on anomaly score and activity metrics
        
        Args:
            row: Single row of activity data
            
        Returns:
            Risk level: "High", "Medium", or "Low"
        """
        score = row['anomaly_score']
        cpu = row['cpu_usage']
        net_out = row['network_out']
        
        # Risk scoring logic
        if score < -0.3 or cpu > 90 or net_out > 800:
            return "High"
        elif score < -0.15 or cpu > 70 or net_out > 500:
            return "Medium"
        else:
            return "Low"


def generate_sample_data(num_records=200):
    """
    Generate simulated cloud activity data for demonstration
    
    Args:
        num_records: Number of records to generate
        
    Returns:
        DataFrame with simulated cloud logs
    """
    np.random.seed(42)
    
    # Generate user IDs
    user_ids = [f"USER_{str(i).zfill(3)}" for i in range(1, num_records + 1)]
    
    # Normal activity patterns (80%)
    normal_count = int(num_records * 0.80)
    normal_data = {
        'user_id': user_ids[:normal_count],
        'login_count': np.random.randint(1, 8, normal_count),
        'cpu_usage': np.random.uniform(20, 65, normal_count),
        'network_in': np.random.uniform(50, 300, normal_count),
        'network_out': np.random.uniform(50, 300, normal_count),
        'login_status': np.random.choice(['success', 'success', 'success', 'failed'], normal_count)
    }
    
    # Anomalous activity patterns (20%)
    anomaly_count = num_records - normal_count
    anomaly_data = {
        'user_id': user_ids[normal_count:],
        'login_count': np.random.randint(8, 25, anomaly_count),
        'cpu_usage': np.random.uniform(70, 99, anomaly_count),
        'network_in': np.random.uniform(400, 950, anomaly_count),
        'network_out': np.random.uniform(400, 950, anomaly_count),
        'login_status': np.random.choice(['success', 'failed', 'failed'], anomaly_count)
    }
    
    # Combine and shuffle
    df_normal = pd.DataFrame(normal_data)
    df_anomaly = pd.DataFrame(anomaly_data)
    df = pd.concat([df_normal, df_anomaly], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Round numerical values
    df['cpu_usage'] = df['cpu_usage'].round(2)
    df['network_in'] = df['network_in'].round(2)
    df['network_out'] = df['network_out'].round(2)
    
    return df


def main():
    """
    Main execution: Generate data, train model, detect threats
    """
    print("=" * 60)
    print("AI-Based Cloud Security Monitoring System")
    print("Anomaly Detection Engine")
    print("=" * 60)
    print()
    
    # Generate sample data
    print("📊 Generating simulated cloud activity data...")
    cloud_data = generate_sample_data(200)
    cloud_data.to_csv('dataset/cloud_logs.csv', index=False)
    print(f"✓ Generated {len(cloud_data)} cloud activity records")
    print()
    
    # Initialize and train detector
    print("🤖 Training Isolation Forest model...")
    detector = CloudSecurityAnomalyDetector(contamination=0.20)
    detector.train(cloud_data)
    print()
    
    # Detect anomalies
    print("🔍 Detecting anomalies...")
    results = detector.detect_anomalies(cloud_data)
    anomalies = results[results['is_anomaly'] == True]
    print(f"✓ Detected {len(anomalies)} anomalies ({len(anomalies)/len(results)*100:.1f}%)")
    print()
    
    # Classify attacks
    print("🚨 Classifying attack types...")
    threats = []
    for idx, row in anomalies.iterrows():
        attack_type = detector.classify_attack_type(row)
        risk_level = detector.calculate_risk_level(row)
        
        threats.append({
            'user_id': row['user_id'],
            'attack_type': attack_type,
            'risk_level': risk_level,
            'cpu_usage': row['cpu_usage'],
            'network_out': row['network_out'],
            'anomaly_score': row['anomaly_score']
        })
    
    # Save detected threats
    threats_df = pd.DataFrame(threats)
    threats_df.to_csv('dataset/detected_threats.csv', index=False)
    print(f"✓ Classified {len(threats)} threats")
    print()
    
    # Summary statistics
    print("📈 Threat Summary:")
    print("-" * 60)
    print(threats_df['attack_type'].value_counts())
    print()
    print("🎯 Risk Level Distribution:")
    print("-" * 60)
    print(threats_df['risk_level'].value_counts())
    print()
    print("=" * 60)
    print("✓ Anomaly detection complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
