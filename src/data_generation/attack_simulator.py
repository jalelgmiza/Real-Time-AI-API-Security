import random
from datetime import datetime, timedelta
from typing import List, Tuple
from ..models.api_models import APILog, UserProfile, AttackType
from .api_data_generator import APIDataGenerator

class AttackSimulator(APIDataGenerator):
    def __init__(self):
        super().__init__()
        
    def generate_credential_stuffing_attack(self, duration_hours: int = 2) -> List[APILog]:
        """Simulate credential stuffing attack"""
        attack_logs = []
        start_time = datetime.now() - timedelta(hours=duration_hours)
        
       
        for minute in range(duration_hours * 60):
            current_time = start_time + timedelta(minutes=minute)
            requests_this_minute = random.randint(50, 100) 
            
            for i in range(requests_this_minute):
                log = APILog(
                    timestamp=current_time + timedelta(seconds=random.randint(0, 59)),
                    user_id=f"attacker_{random.randint(1, 5)}",
                    session_id=f"sess_attack_{minute:04d}_{i:03d}",
                    ip_address=f"10.0.1.{random.randint(1, 10)}",  
                    user_agent=random.choice([
                        "Mozilla/5.0 (compatible; Bot/1.0)",
                        "Python-requests/2.28.1",
                        "curl/7.68.0"
                    ]),
                    endpoint="/api/v1/login",
                    method="POST",
                    parameters={},
                    request_body={
                        "username": self.fake.user_name(),
                        "password": self.fake.password()
                    },
                    response_code=401, 
                    response_time_ms=random.randint(20, 100),
                    bytes_sent=150,
                    bytes_received=80,
                    attack_label=AttackType.CREDENTIAL_STUFFING,
                    attack_type=AttackType.CREDENTIAL_STUFFING,
                    risk_score=0.95,
                    behavioral_anomaly=True
                )
                attack_logs.append(log)
                
        return attack_logs

    def generate_sql_injection_attack(self, duration_hours: int = 1) -> List[APILog]:
        """Simulate SQL injection attempts"""
        attack_logs = []
        start_time = datetime.now() - timedelta(hours=duration_hours)
        
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "UNION SELECT username, password FROM users",
            "' AND 1=CONVERT(int, (SELECT @@version)) --"
        ]
        
        for minute in range(duration_hours * 60):
            current_time = start_time + timedelta(minutes=minute)
            requests_this_minute = random.randint(5, 20) 
            
            for i in range(requests_this_minute):
                endpoint = random.choice(['/api/v1/users', '/api/v1/products', '/api/v1/customers'])
                log = APILog(
                    timestamp=current_time + timedelta(seconds=random.randint(0, 59)),
                    user_id=f"user_{random.randint(1, 50):03d}",
                    session_id=f"sess_sqli_{minute:04d}_{i:03d}",
                    ip_address=self.fake.ipv4(),
                    user_agent=self.fake.user_agent(),
                    endpoint=endpoint,
                    method="GET",
                    parameters={
                        'id': random.choice(sql_payloads),
                        'search': random.choice(sql_payloads) if random.random() > 0.5 else ''
                    },
                    request_body=None,
                    response_code=random.choice([400, 500, 200]),  
                    response_time_ms=random.randint(100, 1000),  
                    bytes_sent=200,
                    bytes_received=150,
                    attack_label=AttackType.SQL_INJECTION,
                    attack_type=AttackType.SQL_INJECTION,
                    risk_score=0.85,
                    behavioral_anomaly=True
                )
                attack_logs.append(log)
                
        return attack_logs

    def generate_data_scraping_attack(self, duration_hours: int = 4) -> List[APILog]:
        """Simulate data scraping attack"""
        attack_logs = []
        start_time = datetime.now() - timedelta(hours=duration_hours)
        
        for minute in range(duration_hours * 60):
            current_time = start_time + timedelta(minutes=minute)
            
           
            requests_this_minute = 8  
            
            for i in range(requests_this_minute):
                log = APILog(
                    timestamp=current_time + timedelta(seconds=random.randint(0, 59)),
                    user_id=f"scraper_bot",
                    session_id=f"sess_scrape_{minute:04d}",
                    ip_address="192.168.10.15", 
                    user_agent="Mozilla/5.0 (compatible; DataScraper/1.0)",
                    endpoint=random.choice(['/api/v1/products', '/api/v1/customers']),
                    method="GET",
                    parameters={
                        'page': (minute * 8 + i) // 10 + 1,  
                        'limit': 100
                    },
                    request_body=None,
                    response_code=200,
                    response_time_ms=random.randint(80, 120),  
                    bytes_sent=180,
                    bytes_received=2500,  
                    attack_label=AttackType.DATA_SCRAPING,
                    attack_type=AttackType.DATA_SCRAPING,
                    risk_score=0.75,
                    behavioral_anomaly=True
                )
                attack_logs.append(log)
                
        return attack_logs

    def generate_complete_dataset(self, normal_hours: int = 24, attack_density: float = 0.05) -> Tuple[List[APILog], List[UserProfile]]:
        """Generate complete dataset with normal traffic and attacks"""
       
        users = self.generate_user_profiles(100)
        
        
        normal_logs = self.generate_normal_traffic(users, normal_hours)
        
        
        total_requests = len(normal_logs)
        attack_count = int(total_requests * attack_density)
        
        attack_logs = []
        
        
        attacks = [
            self.generate_credential_stuffing_attack(1),
            self.generate_sql_injection_attack(1),
            self.generate_data_scraping_attack(2)
        ]
        
        for attack_batch in attacks:
            attack_logs.extend(attack_batch)
            
       
        all_logs = normal_logs + attack_logs
        random.shuffle(all_logs)  
        
        return all_logs, users