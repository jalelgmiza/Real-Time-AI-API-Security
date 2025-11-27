import pandas as pd
import numpy as np
from src.data_generation.attack_simulator import AttackSimulator
from src.detection_engine.feature_engineer import LogFeatureExtractor
from src.detection_engine.anomaly_detector import MultiModelAnomalyDetector
from src.detection_engine.behavioral_analyzer import PatternBehaviorAnalyzer
from src.database.elasticsearch_client import ElasticsearchClient
import json
import os

def main():
    print(" Training ML Models for API Sentinel Pro...")
    
    
    simulator = AttackSimulator()
    feature_extractor = LogFeatureExtractor()
    anomaly_detector = MultiModelAnomalyDetector()
    behavior_analyzer = PatternBehaviorAnalyzer()
    
    try:
        es_client = ElasticsearchClient()
    except Exception as e:
        print(f" Warning: Could not connect to Elasticsearch: {e}")
        es_client = None
    
    print(" Generating training dataset...")
    logs, users = simulator.generate_complete_dataset(normal_hours=48, attack_density=0.1)
    
    
    log_dicts = [log.dict() for log in logs]
    
    print(" Extracting features...")
   
    features_df = feature_extractor.create_complete_feature_set(log_dicts)
    
  
    labels = pd.Series([1 if log.attack_type else 0 for log in logs])
    
    
    features_df = features_df.fillna(0)
    
   
    numeric_features = features_df.select_dtypes(include=[np.number])
    
    print(f" Dataset shape: {numeric_features.shape}")
    print(f" Attack samples: {labels.sum()} ({labels.sum()/len(labels)*100:.1f}%)")
    print(f" Normal samples: {len(labels) - labels.sum()} ({(len(labels) - labels.sum())/len(labels)*100:.1f}%)")
    
    
    print("\n Training anomaly detection models...")
    anomaly_detector.train_all_models(
        features=numeric_features, 
        labels=labels,
        tune_hyperparams=True
    )
    
    print("\n Model training completed!")
    print(" Models saved to ./models/ directory")
    
    
    if os.path.exists('models'):
        model_files = os.listdir('models')
        print(f"\n Saved {len(model_files)} model files:")
        for file in model_files[:10]:  
            print(f"   - {file}")
        if len(model_files) > 10:
            print(f"   ... and {len(model_files) - 10} more")

if __name__ == "__main__":
    main()