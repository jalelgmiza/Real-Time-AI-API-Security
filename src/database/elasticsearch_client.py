from elasticsearch import Elasticsearch
from typing import List, Dict, Any
from datetime import datetime, timedelta
import json
from ..models.api_models import APILog, DetectionResult

class ElasticsearchClient:
    def __init__(self, hosts: List[str] = ['http://localhost:9200']):
        self.client = Elasticsearch(hosts)
        self.api_logs_index = "api-logs"
        self.detection_results_index = "detection-results"
        
    def create_index(self):
        """Create Elasticsearch indices with mappings"""
        
        if not self.client.indices.exists(index=self.api_logs_index):
            mapping = {
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "user_id": {"type": "keyword"},
                        "session_id": {"type": "keyword"},
                        "ip_address": {"type": "ip"},
                        "user_agent": {"type": "text"},
                        "endpoint": {"type": "keyword"},
                        "method": {"type": "keyword"},
                        "parameters": {"type": "object"},
                        "request_body": {"type": "object"},
                        "response_code": {"type": "integer"},
                        "response_time_ms": {"type": "integer"},
                        "bytes_sent": {"type": "integer"},
                        "bytes_received": {"type": "integer"},
                        "attack_label": {"type": "keyword"},
                        "attack_type": {"type": "keyword"},
                        "risk_score": {"type": "float"},
                        "behavioral_anomaly": {"type": "boolean"}
                    }
                }
            }
            self.client.indices.create(index=self.api_logs_index, body=mapping)
            print(f" Created index: {self.api_logs_index}")
        
       
        if not self.client.indices.exists(index=self.detection_results_index):
            mapping = {
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "log_id": {"type": "keyword"},
                        "risk_score": {"type": "float"},
                        "attack_type": {"type": "keyword"},
                        "confidence": {"type": "float"},
                        "features": {"type": "object"},
                        "explanation": {"type": "text"},
                        "action_taken": {"type": "keyword"}
                    }
                }
            }
            self.client.indices.create(index=self.detection_results_index, body=mapping)
            print(f" Created index: {self.detection_results_index}")
    
    def index_log(self, log: APILog):
        """Index a single API log"""
        doc = log.dict()
        doc['timestamp'] = log.timestamp.isoformat()
        self.client.index(index=self.api_logs_index, document=doc)
    
    def index_detection_result(self, result: DetectionResult):
        """Index a detection result"""
        doc = result.dict()
        doc['timestamp'] = result.timestamp.isoformat()
        self.client.index(index=self.detection_results_index, document=doc)
    
    def get_recent_logs(self, hours: int = 1) -> List[Dict]:
        """Get recent logs from Elasticsearch"""
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": f"now-{hours}h/h",
                        "lte": "now/h"
                    }
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": 1000
        }
        
        response = self.client.search(index=self.api_logs_index, body=query)
        return [hit['_source'] for hit in response['hits']['hits']]
    
    def get_logs(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Get logs with pagination"""
        query = {
            "query": {"match_all": {}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "from": offset,
            "size": limit
        }
        
        response = self.client.search(index=self.api_logs_index, body=query)
        return [hit['_source'] for hit in response['hits']['hits']]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get system statistics"""
       
        count_query = {"query": {"match_all": {}}}
        total_logs = self.client.count(index=self.api_logs_index, body=count_query)['count']
        
       
        attack_stats_query = {
            "size": 0,
            "aggs": {
                "attack_types": {
                    "terms": {"field": "attack_type", "size": 10}
                },
                "risk_score_stats": {
                    "stats": {"field": "risk_score"}
                }
            }
        }
        
        attack_stats = self.client.search(index=self.api_logs_index, body=attack_stats_query)
        
        return {
            "total_logs": total_logs,
            "attack_distribution": {
                bucket['key']: bucket['doc_count'] 
                for bucket in attack_stats['aggregations']['attack_types']['buckets']
            },
            "risk_score_stats": attack_stats['aggregations']['risk_score_stats']
        }
    
    def get_alerts(self, high_risk_only: bool = True) -> List[Dict]:
        """Get security alerts"""
        query = {
            "query": {
                "range": {
                    "risk_score": {"gte": 0.7 if high_risk_only else 0.3}
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": 50
        }
        
        response = self.client.search(index=self.api_logs_index, body=query)
        return [hit['_source'] for hit in response['hits']['hits']]