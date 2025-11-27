

# ** Real-Time API Security Monitoring & Anomaly Detection System**

 AI-powered API security platform that leverages cutting-edge machine learning and deep learning techniques to detect and prevent sophisticated API attacks in real-time. Built with an ensemble of 8+ ML models, neural networks, and behavioral analysis, it provides comprehensive protection against modern API threats.

---

##  Key Features

###  Advanced Machine Learning
- **Multi-Model Ensemble**: 8 different ML algorithms working together for robust detection
  - Isolation Forest
  - OneClassSVM
  - Local Outlier Factor
  - Random Forest Classifier
  - XGBoost
  - LightGBM
  - Gradient Boosting
  - Voting Ensemble
- **Deep Learning Models**: Neural networks (DNN & LSTM) for complex pattern recognition
- **Automated Hyperparameter Tuning**: Optimizes model performance automatically
- **Feature Selection**: Intelligent selection of most important features

### Behavioral Analysis
- **User Behavior Profiling**: Tracks and analyzes individual user patterns
- **Request Sequence Analysis**: Detects unusual access patterns and transitions
- **Behavioral Clustering**: Groups similar behaviors using DBSCAN
- **Anomaly Scoring**: Multi-dimensional risk assessment with confidence levels

###  Real-Time Detection
- **Live Monitoring**: Processes API requests in real-time
- **WebSocket Alerts**: Instant notifications for security threats
- **Adaptive Thresholds**: Dynamic threshold calculation based on traffic patterns
- **Model Consensus**: Combines predictions from multiple models for accuracy

###  Interactive Dashboard
- **Real-Time Visualization**: Live traffic graphs and attack distribution
- **Alert Feed**: Detailed security alerts with risk levels
- **System Statistics**: Comprehensive metrics and performance indicators
- **Attack Attribution**: Identifies attack types and affected endpoints

###  Enterprise Integration
- **Elasticsearch Backend**: Scalable storage for logs and detection results
- **RESTful API**: Easy integration with existing systems
- **Configurable Settings**: Flexible configuration for different environments

---

##  System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     API Sentinel Pro                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐      ┌──────────────┐      ┌───────────┐ │
│  │   FastAPI    │◄────►│ Detection    │◄────►│  Models   │ │
│  │   Backend    │      │   Engine     │      │ (8+ ML)   │ │
│  └──────┬───────┘      └──────┬───────┘      └───────────┘ │
│         │                     │                              │
│         │                     │                              │
│  ┌──────▼───────┐      ┌─────▼────────┐      ┌───────────┐ │
│  │  WebSocket   │      │  Behavioral  │      │  Feature  │ │
│  │   Alerts     │      │   Analyzer   │      │ Engineer  │ │
│  └──────────────┘      └──────────────┘      └───────────┘ │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │            Elasticsearch Database                     │   │
│  │  (Logs, Detection Results, User Profiles)            │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         Interactive Web Dashboard                     │   │
│  │  (Real-time Monitoring & Visualization)              │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

##  Detection Engine Components

### 1. **MultiModelAnomalyDetector**
Advanced ensemble-based anomaly detection with:
- **Unsupervised Learning**: Isolation Forest, OneClassSVM, Local Outlier Factor
- **Supervised Learning**: Random Forest, XGBoost, LightGBM, Gradient Boosting
- **Deep Learning**: Neural networks with dropout and early stopping
- **Ensemble Voting**: Combines predictions with weighted averaging
- **Model Persistence**: Saves/loads trained models with joblib

### 2. **PatternBehaviorAnalyzer**
Comprehensive behavioral analysis including:
- **User Profiling**: Tracks request patterns, timing, and endpoints
- **Sequence Tracking**: Analyzes request sequences and transitions
- **Entropy Calculation**: Measures randomness in access patterns
- **Cluster Analysis**: Identifies outliers using DBSCAN clustering
- **Risk Scoring**: Multi-factor risk assessment

### 3. **LogFeatureExtractor**
Intelligent feature engineering with:
- **Time-based Features**: Hour, day, weekend detection
- **Security Features**: SQL injection, XSS detection
- **Behavioral Metrics**: Request frequency, success rates, session duration
- **Real-time Processing**: Sliding window analysis for live data
- **Parameter Analysis**: Suspicious parameter detection

---

##  Installation

### Prerequisites
- **Python**: 3.8 or higher
- **Elasticsearch**: 8.x (running on port 9200)
- **RAM**: Minimum 8GB recommended for model training
- **Disk Space**: ~500MB for models and data

### Step 1: Clone Repository
```bash
git clone <repository-url>
cd api_sentinel_pro
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```



### Step 3: Start Elasticsearch
```bash

docker run -d -p 9200:9200 -p 9300:9300 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  elasticsearch:8.11.0


```

---

## Quick Start

###  Automated Setup 
```bash
python run.py
```

This single command will:
1.  Generate realistic training data (48 hours of traffic)
2.  Train all 8+ ML models with hyperparameter tuning
3.  Start the FastAPI server
4.  Launch the dashboard in your browser


```



##  Dashboard Features

### Real-Time Monitoring
- **Traffic Graph**: Live visualization of API request volume
- **Attack Distribution**: Pie chart showing attack type breakdown
- **Alert Feed**: Real-time security alerts with severity levels
- **System Metrics**: Request counts, anomaly rates, success rates

### Alert Details
Each alert includes:
-  **Risk Score**: 0-100 scale with color coding
-  **Attack Type**: Identified threat category
-  **User/IP**: Source identification
-  **Endpoint**: Targeted API endpoint
-  **Timestamp**: When the threat was detected
-  **Explanation**: Detailed reasoning for the alert

### Risk Levels
-  **CRITICAL** (80-100): Immediate action required
-  **HIGH** (60-79): Significant threat detected
-  **MEDIUM** (40-59): Suspicious activity
-  **LOW** (0-39): Normal with minor anomalies

---

##  Supported Attack Types

### 1. **Credential Stuffing**
- High volume login attempts
- Multiple failed authentication
- Distributed across IPs
- Unusual timing patterns

### 2. **SQL Injection**
- Malicious SQL keywords in parameters
- Database query manipulation attempts
- Union-based attacks
- Boolean-based blind injection

### 3. **Cross-Site Scripting (XSS)**
- Script injection in parameters
- JavaScript payload detection
- Event handler injection
- HTML tag manipulation

### 4. **Data Scraping**
- High-frequency sequential access
- Automated data extraction
- Unusual endpoint patterns
- Rate limit violations

### 5. **Brute Force Attacks**
- Repeated authentication attempts
- Password enumeration
- Account lockout triggers

### 6. **API Abuse**
- Excessive request rates
- Resource exhaustion attempts
- Endpoint enumeration
- Parameter fuzzing

---

##  Configuration

### Model Training Parameters
Edit `train_models.py` to customize:
```python
# Dataset generation
normal_hours = 48          # Hours of normal traffic
attack_density = 0.1       # 10% attack traffic

# Model training
tune_hyperparams = True    # Enable hyperparameter tuning
```

### Detection Thresholds
Adjust in `src/detection_engine/anomaly_detector.py`:
```python

CRITICAL_THRESHOLD = 0.8
HIGH_THRESHOLD = 0.6
MEDIUM_THRESHOLD = 0.4


model_weights = {
    'isolation_forest': 0.15,
    'xgboost': 0.15,
    'neural_network': 0.10,
    # ...
}
```

---

##  Project Structure

```
api_sentinel_pro/
├── data/                           # Generated datasets
│   ├── api_logs.json              # Simulated API logs
│   └── user_profiles.json         # User behavior profiles
│
├── models/                         # Trained ML models
│   ├── isolation_forest.pkl
│   ├── xgboost.pkl
│   ├── lightgbm.pkl
│   ├── neural_network.h5
│   ├── standard_scaler.pkl
│   └── feature_selector.pkl
│
├── src/
│   ├── data_generation/
│   │   ├── attack_simulator.py    # Attack pattern generation
│   │   └── api_data_generator.py  # Normal traffic simulation
│   │
│   ├── detection_engine/
│   │   ├── anomaly_detector.py    # MultiModelAnomalyDetector
│   │   ├── behavioral_analyzer.py # PatternBehaviorAnalyzer
│   │   └── feature_engineer.py    # LogFeatureExtractor
│   │
│   ├── database/
│   │   └── elasticsearch_client.py # Database operations
│   │
│   ├── models/
│   │   └── api_log.py             # Data models
│   │
│   ├── utils/
│   │   └── config_loader.py       # Configuration management
│   │
│   └── main.py                     # FastAPI application
│
├── templates/
│   └── dashboard.html              # Web dashboard UI
│
├── generate_data.py                # Data generation script
├── train_models.py                 # Model training script
├── run.py                          # Main execution script
├── requirements.txt                # Python dependencies
├── CHANGES_SUMMARY.md             # Recent updates documentation
└── README.md                       # This file
```

---



### Feature Importance
Top features for detection:
1. Request frequency (10-minute window)
2. Response time anomalies
3. Endpoint diversity
4. Success rate deviations
5. Time-of-day patterns
6. Parameter anomalies
7. Sequence entropy
8. Cluster distance

### Model Ensemble Strategy
Weighted voting with adaptive thresholds:
- Unsupervised models: 35% weight
- Supervised models: 50% weight
- Neural networks: 15% weight

---




