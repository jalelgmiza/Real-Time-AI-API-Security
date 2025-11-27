import json
import os
from datetime import datetime
from src.data_generation.attack_simulator import AttackSimulator
from src.database.elasticsearch_client import ElasticsearchClient

def main():
    print(" Generating API Sentinel Pro Dataset...")
    
   
    simulator = AttackSimulator()
    
    try:
        es_client = ElasticsearchClient()
        
        
        print(" Creating Elasticsearch index...")
        es_client.create_index()
        elasticsearch_available = True
        
    except Exception as e:
        print(f"  Elasticsearch not available: {e}")
        print(" Continuing with data generation but will save to file only")
        elasticsearch_available = False
        es_client = None
    
    
    print(" Generating normal traffic and attacks...")
    logs, users = simulator.generate_complete_dataset(normal_hours=24, attack_density=0.08)
    

    if elasticsearch_available and es_client:
        print(" Storing data in Elasticsearch...")
        successful_inserts = 0
        for log in logs:
            try:
                es_client.index_log(log)
                successful_inserts += 1
            except Exception as e:
                print(f"  Failed to insert log: {e}")
                continue
        
        print(f" Successfully stored {successful_inserts}/{len(logs)} logs in Elasticsearch")
    
    
    print(" Saving data to JSON files...")
    
   
    os.makedirs('data', exist_ok=True)
 
    with open('data/api_logs.json', 'w') as f:
        log_dicts = [log.dict() for log in logs]
        json.dump(log_dicts, f, indent=2, default=str)
    
   
    with open('data/user_profiles.json', 'w') as f:
        user_dicts = [user.dict() for user in users]
        json.dump(user_dicts, f, indent=2, default=str)
    
    print(f" Generated {len(logs)} API logs")
    print(f" Generated {len(users)} user profiles")
    
    
    attack_counts = {}
    normal_count = 0
    
    for log in logs:
        if log.attack_type and log.attack_type != "NORMAL":
            attack_type = log.attack_type.value
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
        else:
            normal_count += 1
    
    print("\n Traffic Distribution:")
    print(f"  Normal traffic: {normal_count} requests ({(normal_count/len(logs))*100:.2f}%)")
    for attack_type, count in attack_counts.items():
        percentage = (count / len(logs)) * 100
        print(f"  {attack_type}: {count} requests ({percentage:.2f}%)")
   
    summary = {
        "total_logs": len(logs),
        "normal_traffic": normal_count,
        "attack_traffic": sum(attack_counts.values()),
        "attack_breakdown": attack_counts,
        "generated_at": datetime.now().isoformat()
    }
    
    with open('data/generation_summary.json', 'w') as f:
        json.dump(summary, f, indent=2, default=str)

if __name__ == "__main__":
    main()