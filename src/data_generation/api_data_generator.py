import json
import asyncio
from datetime import datetime, timedelta
import random
from typing import List, Dict, Any
import pandas as pd
from faker import Faker
from ..models.api_models import APILog, UserProfile, AttackType

class APIDataGenerator:
    def __init__(self):
        self.fake = Faker()
        self.users = []
        self.departments = ['engineering', 'sales', 'marketing', 'finance', 'hr', 'it']
        self.endpoints = [
            '/api/v1/login', '/api/v1/users', '/api/v1/products', 
            '/api/v1/orders', '/api/v1/customers', '/api/v1/payments',
            '/api/v1/inventory', '/api/v1/reports', '/api/v1/settings'
        ]
        self.methods = ['GET', 'POST', 'PUT', 'DELETE']
        
    def generate_user_profiles(self, count: int = 100) -> List[UserProfile]:
        """Generate realistic user profiles"""
        profiles = []
        for i in range(count):
            dept = random.choice(self.departments)
            profile = UserProfile(
                user_id=f"user_{i:03d}",
                department=dept,
                normal_hours=self._generate_working_hours(dept),
                typical_endpoints=self._get_typical_endpoints(dept),
                access_pattern=random.choice(['web_browser', 'mobile_app', 'api_client']),
                risk_category=random.choice(['low', 'medium', 'high']),
                avg_requests_per_hour=random.uniform(5, 50),
                last_login=self.fake.date_time_this_month()
            )
            profiles.append(profile)
        return profiles

    def _generate_working_hours(self, department: str) -> List[str]:
        """Generate typical working hours based on department"""
        if department in ['engineering', 'it']:
            return ['09:00-18:00', '20:00-23:00'] 
        elif department == 'sales':
            return ['08:00-17:00']
        else:
            return ['09:00-17:00']

    def _get_typical_endpoints(self, department: str) -> List[str]:
        """Get endpoints typically accessed by department"""
        base_endpoints = ['/api/v1/login', '/api/v1/users/profile']
        
        if department == 'engineering':
            return base_endpoints + ['/api/v1/products', '/api/v1/inventory']
        elif department == 'sales':
            return base_endpoints + ['/api/v1/customers', '/api/v1/orders']
        elif department == 'finance':
            return base_endpoints + ['/api/v1/payments', '/api/v1/reports']
        else:
            return base_endpoints

    def generate_normal_traffic(self, users: List[UserProfile], hours: int = 24) -> List[APILog]:
        """Generate normal API traffic"""
        logs = []
        start_time = datetime.now() - timedelta(hours=hours)
        
        for hour in range(hours):
            current_time = start_time + timedelta(hours=hour)
            
            
            if 9 <= current_time.hour <= 17:  
                request_count = random.randint(800, 1200)
            else:
                request_count = random.randint(100, 300)
                
            for _ in range(request_count):
                user = random.choice(users)
                log = self._create_api_log(user, current_time, is_attack=False)
                logs.append(log)
                
        return logs

    def _create_api_log(self, user: UserProfile, timestamp: datetime, is_attack: bool = False) -> APILog:
        """Create a single API log entry"""
        endpoint = random.choice(user.typical_endpoints)
        method = 'GET' if random.random() > 0.3 else 'POST'
        
        # Generate realistic parameters based on endpoint
        parameters = self._generate_parameters(endpoint, method)
        request_body = self._generate_request_body(endpoint, method) if method in ['POST', 'PUT'] else None
        
       
        if is_attack:
            attack_type = random.choice(list(AttackType)).value
            risk_score = random.uniform(0.7, 1.0)
            behavioral_anomaly = True
        else:
            attack_type = None
            risk_score = random.uniform(0.0, 0.3)
            behavioral_anomaly = False
            
        return APILog(
            timestamp=timestamp,
            user_id=user.user_id,
            session_id=f"sess_{self.fake.uuid4()[:8]}",
            ip_address=self.fake.ipv4(),
            user_agent=self.fake.user_agent(),
            endpoint=endpoint,
            method=method,
            parameters=parameters,
            request_body=request_body,
            response_code=self._generate_response_code(attack_type),
            response_time_ms=random.randint(50, 500),
            bytes_sent=random.randint(100, 5000),
            bytes_received=random.randint(50, 2000),
            attack_label=AttackType.NORMAL if not is_attack else AttackType(attack_type),
            attack_type=AttackType(attack_type) if is_attack else None,
            risk_score=risk_score,
            behavioral_anomaly=behavioral_anomaly
        )

    def _generate_parameters(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Generate realistic parameters based on endpoint"""
        if 'products' in endpoint and method == 'GET':
            return {'page': random.randint(1, 10), 'limit': random.choice([10, 25, 50])}
        elif 'customers' in endpoint:
            return {'search': self.fake.last_name() if random.random() > 0.7 else ''}
        elif 'orders' in endpoint:
            return {'status': random.choice(['pending', 'completed', 'cancelled'])}
        else:
            return {}

    def _generate_request_body(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Generate realistic request body"""
        if endpoint == '/api/v1/login' and method == 'POST':
            return {
                'username': self.fake.user_name(),
                'password': 'encrypted_password'
            }
        elif 'orders' in endpoint and method == 'POST':
            return {
                'product_id': f"prod_{random.randint(1000, 9999)}",
                'quantity': random.randint(1, 5),
                'customer_id': f"cust_{random.randint(100, 999)}"
            }
        elif 'payments' in endpoint and method == 'POST':
            return {
                'amount': round(random.uniform(10, 1000), 2),
                'currency': 'USD',
                'payment_method': random.choice(['credit_card', 'paypal', 'bank_transfer'])
            }
        return {}

    def _generate_response_code(self, attack_type: str) -> int:
        """Generate appropriate response code"""
        if attack_type in [AttackType.CREDENTIAL_STUFFING.value, AttackType.SQL_INJECTION.value]:
            return random.choice([401, 403, 500])  
        else:
            return random.choices([200, 201, 400, 401, 404], weights=[70, 10, 8, 7, 5])[0]