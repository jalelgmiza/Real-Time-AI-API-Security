import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.feature_selection import SelectFromModel
import xgboost as xgb
import lightgbm as lgb
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, LSTM
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping
import joblib
import warnings
import os
warnings.filterwarnings('ignore')

class MultiModelAnomalyDetector:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_selector = None
        self.is_trained = False
        self._setup_models()
        
    def _setup_models(self):
        """Initialize multiple ML models for ensemble detection"""
      
        self.models['isolation_forest'] = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=200,
            max_samples='auto'
        )
        
        self.models['svm_anomaly'] = OneClassSVM(
            nu=0.1,
            kernel='rbf',
            gamma='scale'
        )
        
        self.models['local_outlier'] = LocalOutlierFactor(
            n_neighbors=20,
            contamination=0.1,
            novelty=True
        )
        
        
        self.models['random_forest'] = RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight='balanced',
            max_depth=10
        )
        
        self.models['xgboost'] = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            random_state=42,
            scale_pos_weight=1
        )
        
        self.models['lightgbm'] = lgb.LGBMClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            random_state=42,
            class_weight='balanced'
        )
        
        self.models['gradient_boosting'] = GradientBoostingClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            random_state=42
        )
        
        
        self.models['model_ensemble'] = VotingClassifier(
            estimators=[
                ('rf', self.models['random_forest']),
                ('xgb', self.models['xgboost']),
                ('lgb', self.models['lightgbm'])
            ],
            voting='soft'
        )
        
     
        self.scalers['standard'] = StandardScaler()
        self.scalers['robust'] = RobustScaler()
        
    def build_neural_network(self, input_dim):
        """Create deep learning model for anomaly detection"""
        model = Sequential([
            Dense(128, activation='relu', input_shape=(input_dim,)),
            Dropout(0.3),
            Dense(64, activation='relu'),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def build_sequence_model(self, timesteps, features):
        """Create LSTM model for sequential pattern detection"""
        model = Sequential([
            LSTM(64, return_sequences=True, input_shape=(timesteps, features)),
            Dropout(0.2),
            LSTM(32, return_sequences=False),
            Dropout(0.2),
            Dense(16, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def train_all_models(self, features: pd.DataFrame, labels: pd.Series = None, 
                        tune_hyperparams: bool = True):
        """Train complete model ensemble with optional hyperparameter tuning"""
        print(" Training ML model ensemble...")
        
       
        os.makedirs('models', exist_ok=True)
        
    
        feature_columns = [col for col in features.columns if col not in ['is_attack', 'attack_type']]
        X = features[feature_columns]
        
      
        X = self._clean_missing_data(X)
        
        
        X_selected = self._select_important_features(X, labels)
        
        
        X_scaled_standard = self.scalers['standard'].fit_transform(X_selected)
        X_scaled_robust = self.scalers['robust'].fit_transform(X_selected)
        
       
        print(" Training unsupervised detectors...")
        self.models['isolation_forest'].fit(X_scaled_standard)
        self.models['svm_anomaly'].fit(X_scaled_standard)
        self.models['local_outlier'].fit(X_scaled_standard)
        
        print(" Unsupervised models ready")
        
       
        if labels is not None:
            print(" Training supervised classifiers...")
            
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled_standard, labels, test_size=0.2, random_state=42, stratify=labels
            )
            
            
            if tune_hyperparams:
                self._tune_model_parameters(X_train, y_train)
            
            
            for name, model in self.models.items():
                if name not in ['isolation_forest', 'svm_anomaly', 'local_outlier']:
                    print(f"Training {name}...")
                    model.fit(X_train, y_train)
                    
                   
                    y_pred = model.predict(X_test)
                    y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else model.decision_function(X_test)
                    
                    print(f"\n{name.upper()} Results:")
                    print(classification_report(y_test, y_pred))
                    print(f"ROC AUC: {roc_auc_score(y_test, y_proba):.4f}")
            
           
            print(" Training Neural Network...")
            self.nn_model = self.build_neural_network(X_train.shape[1])
            
            early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
            
            history = self.nn_model.fit(
                X_train, y_train,
                epochs=100,
                batch_size=32,
                validation_split=0.2,
                callbacks=[early_stopping],
                verbose=0
            )
            
            nn_pred = (self.nn_model.predict(X_test) > 0.5).astype(int).flatten()
            print("\nNEURAL NETWORK Performance:")
            print(classification_report(y_test, nn_pred))
            
            self.is_trained = True
        
        
        self._save_trained_models()
        print(" All models trained and saved")
    
    def _clean_missing_data(self, X: pd.DataFrame) -> pd.DataFrame:
        """Handle missing values in the dataset"""
        
        numerical_cols = X.select_dtypes(include=[np.number]).columns
        X[numerical_cols] = X[numerical_cols].fillna(X[numerical_cols].median())
        
     
        categorical_cols = X.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            X[col] = X[col].fillna(X[col].mode()[0] if len(X[col].mode()) > 0 else 'missing')
        
        return X
    
    def _select_important_features(self, X: pd.DataFrame, labels: pd.Series = None) -> pd.DataFrame:
        """Select most important features using multiple methods"""
        if labels is not None:
        
            selector = SelectFromModel(
                RandomForestClassifier(n_estimators=100, random_state=42),
                threshold='median'
            )
            X_selected = selector.fit_transform(X, labels)
            self.feature_selector = selector
            print(f" Selected {X_selected.shape[1]} features from {X.shape[1]} original features")
            return X_selected
        else:
           
            return X.values
    
    def _tune_model_parameters(self, X_train, y_train):
        """Optimize hyperparameters for key models"""
        print(" Tuning model parameters...")
        
        
        rf_param_dist = {
            'n_estimators': [100, 200, 300],
            'max_depth': [5, 10, 15, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        
        rf_search = RandomizedSearchCV(
            self.models['random_forest'], rf_param_dist, n_iter=10, 
            cv=3, random_state=42, n_jobs=-1
        )
        rf_search.fit(X_train, y_train)
        self.models['random_forest'] = rf_search.best_estimator_
        print(f" Random Forest tuned: {rf_search.best_params_}")
    
    def detect_anomalies(self, features: pd.DataFrame) -> pd.DataFrame:
        """Detect anomalies using ensemble of all models"""
        if not self.is_trained:
            self._load_saved_models()
            
        
        feature_columns = [col for col in features.columns if col not in ['is_attack', 'attack_type']]
        X = features[feature_columns]
        X = self._clean_missing_data(X)
        
        if self.feature_selector:
            X_selected = self.feature_selector.transform(X)
        else:
            X_selected = X.values
            
        X_scaled = self.scalers['standard'].transform(X_selected)
        
        
        model_predictions = {}
        
       
        model_predictions['isolation_forest'] = self.models['isolation_forest'].decision_function(X_scaled)
        model_predictions['svm_anomaly'] = self.models['svm_anomaly'].decision_function(X_scaled)
        model_predictions['local_outlier'] = self.models['local_outlier'].decision_function(X_scaled)
        
     
        for model_name, scores in model_predictions.items():
            model_predictions[model_name] = 1 / (1 + np.exp(-scores))
        
       
        if self.is_trained:
            for name, model in self.models.items():
                if name not in ['isolation_forest', 'svm_anomaly', 'local_outlier']:
                    if hasattr(model, 'predict_proba'):
                        model_predictions[name] = model.predict_proba(X_scaled)[:, 1]
                    else:
                        model_predictions[name] = model.decision_function(X_scaled)
            
           
            model_predictions['neural_network'] = self.nn_model.predict(X_scaled).flatten()
        
      
        model_weights = {
            'isolation_forest': 0.15,
            'svm_anomaly': 0.10,
            'local_outlier': 0.10,
            'random_forest': 0.15,
            'xgboost': 0.15,
            'lightgbm': 0.15,
            'gradient_boosting': 0.10,
            'model_ensemble': 0.10
        }
        
        combined_score = np.zeros(len(X))
        for model_name, weight in model_weights.items():
            if model_name in model_predictions:
                combined_score += weight * model_predictions[model_name]
        
       
        threshold = self._calculate_adaptive_threshold(combined_score)
        final_prediction = (combined_score > threshold).astype(int)
        
     
        confidence = np.abs(combined_score - 0.5) * 2  
        
        results = pd.DataFrame({
            'combined_risk_score': combined_score,
            'prediction': final_prediction,
            'confidence': confidence,
            'risk_level': self._assign_risk_category(combined_score, confidence),
            'final_anomaly_score': combined_score * confidence,
            'model_agreement': self._calculate_model_consensus(model_predictions)
        })
        
        
        for model_name, scores in model_predictions.items():
            results[f'{model_name}_score'] = scores
        
        return results
    
    def _calculate_adaptive_threshold(self, scores: np.ndarray) -> float:
        """Calculate dynamic threshold based on score distribution"""
        
        threshold = np.percentile(scores, 95)  
        return max(0.5, threshold) 
    
    def _calculate_model_consensus(self, predictions: dict) -> np.ndarray:
        """Calculate agreement between different models"""
        if len(predictions) == 0:
            return np.zeros(1)
        
        
        binary_predictions = {}
        for model_name, scores in predictions.items():
            binary_predictions[model_name] = (scores > 0.5).astype(int)
        
       
        all_predictions = np.array(list(binary_predictions.values()))
        majority_vote = (np.mean(all_predictions, axis=0) > 0.5).astype(int)
        
        agreement = np.mean(all_predictions == majority_vote, axis=0)
        return agreement
    
    def _assign_risk_category(self, scores: np.ndarray, confidence: np.ndarray) -> list:
        """Assign risk levels based on scores and confidence"""
        risk_levels = []
        for score, conf in zip(scores, confidence):
            if score > 0.8 and conf > 0.7:
                risk_levels.append('CRITICAL')
            elif score > 0.6 and conf > 0.5:
                risk_levels.append('HIGH')
            elif score > 0.4:
                risk_levels.append('MEDIUM')
            else:
                risk_levels.append('LOW')
        return risk_levels
    
    def _save_trained_models(self):
        """Save all trained models"""
        for name, model in self.models.items():
            joblib.dump(model, f'models/{name}.pkl')
        
        for name, scaler in self.scalers.items():
            joblib.dump(scaler, f'models/{name}_scaler.pkl')
            
        if hasattr(self, 'feature_selector') and self.feature_selector:
            joblib.dump(self.feature_selector, 'models/feature_selector.pkl')
    
    def _load_saved_models(self):
        """Load pre-trained models"""
        try:
            for name in self.models.keys():
                self.models[name] = joblib.load(f'models/{name}.pkl')
            
            for name in self.scalers.keys():
                self.scalers[name] = joblib.load(f'models/{name}_scaler.pkl')
            
            self.feature_selector = joblib.load('models/feature_selector.pkl')
            self.is_trained = True
            print(" Models loaded successfully")
        except FileNotFoundError:
            print(" No trained models found. Please train models first.")