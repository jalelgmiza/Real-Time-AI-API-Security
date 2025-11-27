import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
import statistics
from typing import Dict, List, Any
from sklearn.cluster import DBSCAN
import math

class UserBehaviorAnalyzer:
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.user_profiles = defaultdict(lambda: {
            'request_times': deque(maxlen=window_size),
            'endpoints': deque(maxlen=window_size),
            'response_times': deque(maxlen=window_size),
            'success_rates': deque(maxlen=window_size),
            'last_activity': None
        })
        
    def analyze_user_behavior(self, log: Dict) -> Dict[str, Any]:
        """Analyze behavioral patterns for a single log entry"""
        user_id = log['user_id']
        user_profile = self.user_profiles[user_id]
        
      
        current_time = log['timestamp']
        user_profile['request_times'].append(current_time)
        user_profile['endpoints'].append(log['endpoint'])
        user_profile['response_times'].append(log['response_time_ms'])
        user_profile['success_rates'].append(1 if log['response_code'] in [200, 201] else 0)
        user_profile['last_activity'] = current_time
        
        detected_anomalies = {
            'unusual_timing': self._check_timing_anomaly(user_profile, log),
            'unusual_endpoint': self._check_endpoint_anomaly(user_profile, log),
            'response_time_spike': self._check_response_time_anomaly(user_profile, log),
            'high_request_rate': self._check_rate_anomaly(user_profile, log),
            'success_rate_drop': self._check_success_rate_anomaly(user_profile, log),
        }
        
        
        risk_factors = [1 for anomaly in detected_anomalies.values() if anomaly]
        behavior_risk_score = len(risk_factors) / len(detected_anomalies) if detected_anomalies else 0
        
        return {
            'detected_anomalies': detected_anomalies,
            'behavior_risk_score': behavior_risk_score,
            'suspicious_behavior': behavior_risk_score > 0.3
        }
    
    def _check_timing_anomaly(self, profile: Dict, log: Dict) -> bool:
        """Check for unusual access timing patterns"""
        if len(profile['request_times']) < 10:
            return False
            
        request_hour = log['timestamp'].hour
        historical_hours = [t.hour for t in profile['request_times']]
        
        hour_frequency = historical_hours.count(request_hour) / len(historical_hours)
        return hour_frequency < 0.1
    
    def _check_endpoint_anomaly(self, profile: Dict, log: Dict) -> bool:
        """Check if user is accessing unusual endpoints"""
        if len(profile['endpoints']) < 10:
            return False
            
        current_endpoint = log['endpoint']
        endpoint_counts = defaultdict(int)
        for endpoint in profile['endpoints']:
            endpoint_counts[endpoint] += 1
            
        total_requests = len(profile['endpoints'])
        endpoint_frequency = endpoint_counts[current_endpoint] / total_requests
        
        return endpoint_frequency < 0.05
    
    def _check_response_time_anomaly(self, profile: Dict, log: Dict) -> bool:
        """Check for unusual response times"""
        if len(profile['response_times']) < 10:
            return False
            
        current_rt = log['response_time_ms']
        historical_rts = list(profile['response_times'])
        
        mean_rt = statistics.mean(historical_rts)
        std_rt = statistics.stdev(historical_rts) if len(historical_rts) > 1 else mean_rt * 0.5
        
        return abs(current_rt - mean_rt) > 3 * std_rt
    
    def _check_rate_anomaly(self, profile: Dict, log: Dict) -> bool:
        """Check for unusually high request rates"""
        if len(profile['request_times']) < 20:
            return False
            
        recent_window = log['timestamp'] - timedelta(minutes=5)
        recent_requests = [t for t in profile['request_times'] if t > recent_window]
        current_rate = len(recent_requests)
        
        return current_rate > 50
    
    def _check_success_rate_anomaly(self, profile: Dict, log: Dict) -> bool:
        """Check for drops in success rates"""
        if len(profile['success_rates']) < 10:
            return False
            
        current_success = 1 if log['response_code'] in [200, 201] else 0
        historical_success_rate = statistics.mean(profile['success_rates'])
        
        return historical_success_rate > 0.8 and current_success == 0


class PatternBehaviorAnalyzer(UserBehaviorAnalyzer):
    def __init__(self, window_size: int = 1000):
        super().__init__(window_size)
        self.sequence_tracker = RequestSequenceTracker()
        self.behavior_clusterer = BehaviorClusterAnalyzer()
        
    def analyze_comprehensive_behavior(self, log: Dict, historical_logs: List[Dict]) -> Dict[str, Any]:
        """Comprehensive behavioral analysis with pattern recognition"""
        basic_analysis = self.analyze_user_behavior(log)
        
        
        sequence_analysis = self.sequence_tracker.analyze_request_sequence(
            log, historical_logs
        )
        
       
        cluster_analysis = self.behavior_clusterer.analyze_behavior_clusters(
            log, historical_logs
        )
        
        
        comprehensive_analysis = {
            **basic_analysis,
            'sequence_patterns': sequence_analysis,
            'cluster_behavior': cluster_analysis,
            'comprehensive_risk_score': self._compute_overall_risk(
                basic_analysis, sequence_analysis, cluster_analysis
            )
        }
        
        return comprehensive_analysis
    
    def _compute_overall_risk(self, basic_analysis: Dict, 
                            sequence_analysis: Dict, 
                            cluster_analysis: Dict) -> float:
        """Compute overall risk score from all analyses"""
        weights = {
            'basic_risk': 0.4,
            'sequence_risk': 0.3,
            'cluster_risk': 0.3
        }
        
        basic_risk = basic_analysis['behavior_risk_score']
        sequence_risk = sequence_analysis.get('sequence_anomaly_score', 0)
        cluster_risk = cluster_analysis.get('cluster_anomaly_score', 0)
        
        overall_risk = (
            weights['basic_risk'] * basic_risk +
            weights['sequence_risk'] * sequence_risk +
            weights['cluster_risk'] * cluster_risk
        )
        
        return min(overall_risk, 1.0)


class RequestSequenceTracker:
    """Track and analyze sequential request patterns"""
    
    def __init__(self):
        self.user_sequences = defaultdict(lambda: deque(maxlen=20))
        
    def analyze_request_sequence(self, log: Dict, historical_logs: List[Dict]) -> Dict[str, Any]:
        """Analyze sequential access patterns"""
        user_id = log['user_id']
        current_sequence = self.user_sequences[user_id]
        current_sequence.append(log['endpoint'])
        
        if len(current_sequence) < 5:
            return {'sequence_anomaly_score': 0, 'sequence_anomaly': False}
        
      
        sequence_entropy = self._calculate_sequence_entropy(current_sequence)
        transition_anomaly = self._detect_unusual_transitions(current_sequence)
        pattern_deviation = self._calculate_pattern_deviation(current_sequence, historical_logs)
        
        sequence_anomaly_score = (sequence_entropy + transition_anomaly + pattern_deviation) / 3
        
        return {
            'sequence_anomaly_score': sequence_anomaly_score,
            'sequence_anomaly': sequence_anomaly_score > 0.7,
            'sequence_entropy': sequence_entropy,
            'transition_anomaly': transition_anomaly,
            'pattern_deviation': pattern_deviation
        }
    
    def _calculate_sequence_entropy(self, sequence: deque) -> float:
        """Calculate entropy of the sequence (higher entropy = more random)"""
        if len(sequence) < 2:
            return 0.0
        
        counter = Counter(sequence)
        sequence_length = len(sequence)
        entropy = 0.0
        
        for count in counter.values():
            probability = count / sequence_length
            entropy -= probability * math.log2(probability)
        
        
        max_entropy = math.log2(len(counter))
        return entropy / max_entropy if max_entropy > 0 else 0.0
    
    def _detect_unusual_transitions(self, sequence: deque) -> float:
        """Detect unusual transitions between endpoints"""
        if len(sequence) < 2:
            return 0.0
        
        transitions = []
        for i in range(len(sequence) - 1):
            transitions.append(f"{sequence[i]}->{sequence[i + 1]}")
        
        
        transition_counts = Counter(transitions)
        latest_transition = transitions[-1] if transitions else ""
        
        if latest_transition and len(transitions) > 1:
            transition_freq = transition_counts[latest_transition] / len(transitions)
            return 1.0 - transition_freq
        
        return 0.0
    
    def _calculate_pattern_deviation(self, current_sequence: deque, historical_logs: List[Dict]) -> float:
        """Calculate deviation from historical patterns"""
        return 0.0


class BehaviorClusterAnalyzer:
    """Analyze behavioral clusters for anomaly detection"""
    
    def __init__(self):
        self.cluster_model = DBSCAN(eps=0.5, min_samples=5)
        self.behavior_vectors = []
        
    def analyze_behavior_clusters(self, log: Dict, historical_logs: List[Dict]) -> Dict[str, Any]:
        """Analyze if behavior fits into existing clusters"""
        behavior_vector = self._create_behavior_vector(log, historical_logs)
        self.behavior_vectors.append(behavior_vector)
        
        if len(self.behavior_vectors) < 10:
            return {'cluster_anomaly_score': 0, 'cluster_anomaly': False}
        
        try:
            clusters = self.cluster_model.fit_predict(self.behavior_vectors)
            current_cluster = clusters[-1] if len(clusters) > 0 else -1
            
            cluster_sizes = Counter(clusters)
            current_cluster_size = cluster_sizes.get(current_cluster, 0)
            total_points = len(clusters)
            
            if current_cluster == -1:
                anomaly_score = 1.0
            else:
                cluster_proportion = current_cluster_size / total_points
                anomaly_score = 1.0 - cluster_proportion
            
            return {
                'cluster_anomaly_score': anomaly_score,
                'cluster_anomaly': anomaly_score > 0.8,
                'cluster_id': current_cluster,
                'cluster_size': current_cluster_size
            }
            
        except Exception as e:
            return {'cluster_anomaly_score': 0, 'cluster_anomaly': False, 'error': str(e)}
    
    def _create_behavior_vector(self, log: Dict, historical_logs: List[Dict]) -> list:
        """Create numerical vector representing user behavior"""
        user_logs = [l for l in historical_logs if l['user_id'] == log['user_id']]
        
        vector = [
            len(user_logs),
            log['response_time_ms'],
            len(set(l['endpoint'] for l in user_logs)),
            np.mean([l.get('response_time_ms', 0) for l in user_logs[-10:]]),
        ]
        
        return vector