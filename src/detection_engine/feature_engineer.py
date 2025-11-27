import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Any
from collections import defaultdict
import hashlib

class LogFeatureExtractor:
    def __init__(self):
        self.analysis_window = timedelta(minutes=10)
        
    def extract_log_features(self, logs: List[Dict]) -> pd.DataFrame:
        """Extract features from API logs for ML modeling"""
        feature_list = []
        
        for log in logs:
            feature_set = {
             
                'hour_of_day': log['timestamp'].hour,
                'day_of_week': log['timestamp'].weekday(),
                'is_weekend': 1 if log['timestamp'].weekday() >= 5 else 0,
                'response_time_ms': log['response_time_ms'],
                'bytes_sent': log['bytes_sent'],
                'bytes_received': log['bytes_received'],
                'response_code': log['response_code'],
                
                
                'endpoint_hash': self._hash_endpoint(log['endpoint']),
                'method_code': self._encode_http_method(log['method']),
                
              
                'user_request_frequency': 0, 
                'ip_request_frequency': 0,    
                'endpoint_popularity': 0,     
            }
            
      
            feature_set.update(self._extract_security_features(log))
            feature_list.append(feature_set)
            
        return pd.DataFrame(feature_list)
    
    def _hash_endpoint(self, endpoint: str) -> int:
        """Convert endpoint to numerical hash"""
        return int(hashlib.md5(endpoint.encode()).hexdigest()[:8], 16) % 1000
    
    def _encode_http_method(self, method: str) -> int:
        """Encode HTTP method as integer"""
        method_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3, 'PATCH': 4}
        return method_map.get(method, 5)
    
    def _extract_security_features(self, log: Dict) -> Dict[str, Any]:
        """Extract security-related features from request parameters"""
        features = {}
        
        
        param_count = len(log.get('parameters', {}))
        features['parameter_count'] = param_count
        
       
        body_size = 0
        if log.get('request_body'):
            body_size = len(str(log['request_body']))
        features['request_body_size'] = body_size
        
        
        sql_keywords = ['select', 'union', 'drop', 'insert', 'update', 'delete', 'or', 'and']
        sql_indicator = 0
        for param_value in log.get('parameters', {}).values():
            if any(keyword in str(param_value).lower() for keyword in sql_keywords):
                sql_indicator = 1
                break
        features['sql_injection_indicator'] = sql_indicator
        
      
        xss_patterns = ['<script>', 'javascript:', 'onload=', 'onerror=']
        xss_indicator = 0
        for param_value in log.get('parameters', {}).values():
            if any(pattern in str(param_value).lower() for pattern in xss_patterns):
                xss_indicator = 1
                break
        features['xss_indicator'] = xss_indicator
        
       
        suspicious_params = ['password', 'token', 'key', 'secret', 'auth']
        suspicious_param_count = 0
        for param_name in log.get('parameters', {}).keys():
            if any(suspicious in param_name.lower() for suspicious in suspicious_params):
                suspicious_param_count += 1
        features['suspicious_parameter_count'] = suspicious_param_count
        
        return features
    
    def compute_behavior_features(self, current_log: Dict, historical_logs: List[Dict]) -> Dict[str, Any]:
        """Compute behavioral features based on historical data"""
        user_logs = [log for log in historical_logs if log['user_id'] == current_log['user_id']]
        ip_logs = [log for log in historical_logs if log['ip_address'] == current_log['ip_address']]
        
       
        time_threshold = current_log['timestamp'] - self.analysis_window
        recent_user_logs = [log for log in user_logs if log['timestamp'] >= time_threshold]
        recent_ip_logs = [log for log in ip_logs if log['timestamp'] >= time_threshold]
        
        return {
            'user_request_frequency': len(recent_user_logs),
            'ip_request_frequency': len(recent_ip_logs),
            'user_success_rate': self._calculate_success_rate(user_logs),
            'ip_success_rate': self._calculate_success_rate(ip_logs),
            'user_endpoint_diversity': len(set(log['endpoint'] for log in user_logs)),
            'ip_endpoint_diversity': len(set(log['endpoint'] for log in ip_logs)),
            'user_avg_response_time': self._calculate_avg_response_time(user_logs),
            'ip_avg_response_time': self._calculate_avg_response_time(ip_logs),
            'user_session_duration': self._calculate_session_duration(user_logs),
        }
    
    def _calculate_success_rate(self, logs: List[Dict]) -> float:
        """Calculate success rate from response codes"""
        if not logs:
            return 0.0
        success_codes = [200, 201, 202]
        successful_requests = sum(1 for log in logs if log['response_code'] in success_codes)
        return successful_requests / len(logs)
    
    def _calculate_avg_response_time(self, logs: List[Dict]) -> float:
        """Calculate average response time"""
        if not logs:
            return 0.0
        response_times = [log.get('response_time_ms', 0) for log in logs]
        return np.mean(response_times)
    
    def _calculate_session_duration(self, logs: List[Dict]) -> float:
        """Calculate session duration in seconds"""
        if len(logs) < 2:
            return 0.0
        timestamps = [log['timestamp'] for log in logs]
        return (max(timestamps) - min(timestamps)).total_seconds()
    
    def create_complete_feature_set(self, logs: List[Dict]) -> pd.DataFrame:
        """Create complete feature set including behavioral patterns"""
        base_features = self.extract_log_features(logs)
        complete_features = []
        
        for i, log in enumerate(logs):
            historical_logs = logs[:i]
            
            behavior_features = self.compute_behavior_features(log, historical_logs)
            
            combined_features = {**base_features.iloc[i].to_dict(), **behavior_features}
            complete_features.append(combined_features)
        
        return pd.DataFrame(complete_features)


class RealTimeFeatureEngine(LogFeatureExtractor):
    """Feature engine optimized for real-time processing"""
    
    def __init__(self):
        super().__init__()
        self.user_activity = defaultdict(list)
        self.ip_activity = defaultdict(list)
        self.endpoint_metrics = defaultdict(lambda: {'count': 0, 'response_times': []})
        
    def process_log_realtime(self, log: Dict) -> Dict[str, Any]:
        """Process single log in real-time and extract features"""
        
        self.user_activity[log['user_id']].append(log)
        self.ip_activity[log['ip_address']].append(log)
        
      
        endpoint = log['endpoint']
        self.endpoint_metrics[endpoint]['count'] += 1
        self.endpoint_metrics[endpoint]['response_times'].append(log['response_time_ms'])
        
       
        one_hour_ago = log['timestamp'] - timedelta(hours=1)
        self.user_activity[log['user_id']] = [
            h for h in self.user_activity[log['user_id']] if h['timestamp'] > one_hour_ago
        ]
        self.ip_activity[log['ip_address']] = [
            h for h in self.ip_activity[log['ip_address']] if h['timestamp'] > one_hour_ago
        ]
        
        
        features = self.extract_log_features([log]).iloc[0].to_dict()
        
      
        realtime_features = self._compute_realtime_metrics(log)
        features.update(realtime_features)
        
        return features
    
    def _compute_realtime_metrics(self, log: Dict) -> Dict[str, Any]:
        """Compute real-time metrics using sliding windows"""
        user_recent = self.user_activity[log['user_id']][-50:]
        ip_recent = self.ip_activity[log['ip_address']][-100:]
        
       
        ten_min_ago = log['timestamp'] - timedelta(minutes=10)
        user_recent_10min = [h for h in user_recent if h['timestamp'] > ten_min_ago]
        ip_recent_10min = [h for h in ip_recent if h['timestamp'] > ten_min_ago]
        
        return {
            'user_requests_10min': len(user_recent_10min),
            'ip_requests_10min': len(ip_recent_10min),
            'user_requests_1min': len([h for h in user_recent if h['timestamp'] > log['timestamp'] - timedelta(minutes=1)]),
            'ip_requests_1min': len([h for h in ip_recent if h['timestamp'] > log['timestamp'] - timedelta(minutes=1)]),
            'endpoint_popularity': self.endpoint_metrics[log['endpoint']]['count'],
            'avg_endpoint_response_time': np.mean(self.endpoint_metrics[log['endpoint']]['response_times'][-100:]) if self.endpoint_metrics[log['endpoint']]['response_times'] else 0,
        }