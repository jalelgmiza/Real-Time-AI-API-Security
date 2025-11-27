from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import asyncio
import json
import uvicorn
from typing import List, Dict, Any
import pandas as pd

from .models.api_models import APILog, DetectionResult
from .database.elasticsearch_client import ElasticsearchClient
from .detection_engine.feature_engineer import LogFeatureExtractor, RealTimeFeatureEngine
from .detection_engine.anomaly_detector import MultiModelAnomalyDetector
from .detection_engine.behavioral_analyzer import PatternBehaviorAnalyzer, UserBehaviorAnalyzer

app = FastAPI(title="API Sentinel Pro", version="2.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")


es_client = ElasticsearchClient()
feature_extractor = LogFeatureExtractor()
realtime_feature_engine = RealTimeFeatureEngine()
anomaly_detector = MultiModelAnomalyDetector()
behavioral_analyzer = PatternBehaviorAnalyzer()


active_connections: List[WebSocket] = []

@app.on_event("startup")
async def startup_event():
    """Initialize components on startup"""
    print(" API Sentinel Pro Starting...")
   
    try:
        anomaly_detector._load_saved_models()
        print(" ML Models loaded successfully")
    except Exception as e:
        print(f" Warning: Could not load models: {e}")
        print("   Models will need to be trained first")

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy", 
        "service": "API Sentinel Pro",
        "version": "2.0.0",
        "models_loaded": anomaly_detector.is_trained
    }

@app.post("/api/detect")
async def detect_anomalies(background_tasks: BackgroundTasks):
    """Trigger anomaly detection on recent logs"""
    try:
        
        recent_logs = es_client.get_recent_logs(hours=1)
        
        if not recent_logs:
            return {"message": "No recent logs found", "anomalies_detected": 0}
        
        
        results = await process_logs_for_detection(recent_logs)
        
        
        for result in results:
            es_client.index_detection_result(result)
        
        
        high_risk_count = len([r for r in results if r.risk_score > 0.7])
        await notify_websockets({
            "type": "detection_complete",
            "anomalies_detected": high_risk_count,
            "total_processed": len(results)
        })
        
        return {
            "message": "Anomaly detection completed",
            "anomalies_detected": high_risk_count,
            "total_processed": len(results)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")

@app.get("/api/logs")
async def get_logs(limit: int = 100, offset: int = 0):
    """Get API logs with pagination"""
    logs = es_client.get_logs(limit=limit, offset=offset)
    return {"logs": logs, "total": len(logs)}

@app.get("/api/stats")
async def get_stats():
    """Get system statistics"""
    stats = es_client.get_statistics()
    return stats

@app.get("/api/alerts")
async def get_alerts(high_risk_only: bool = True):
    """Get security alerts"""
    alerts = es_client.get_alerts(high_risk_only=high_risk_only)
    return {"alerts": alerts}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time updates"""
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)

async def process_logs_for_detection(logs: List[Dict]) -> List[DetectionResult]:
    """Process logs through the enhanced detection pipeline"""
    results = []
    
  
    log_dicts = []
    for log_dict in logs:
        try:
            log = APILog(**log_dict)
            log_dicts.append(log.dict())
        except Exception as e:
            print(f" Skipping invalid log: {e}")
            continue
    
    if not log_dicts:
        return results
    
   
    features_df = feature_extractor.create_complete_feature_set(log_dicts)
    
    
    detection_results_df = anomaly_detector.detect_anomalies(features_df)
    
   
    for i, log_dict in enumerate(log_dicts):
        try:
            log = APILog(**log_dict)
            
          
            behavioral_result = behavioral_analyzer.analyze_comprehensive_behavior(
                log_dict, 
                log_dicts[:i]  
            )
            
           
            detection_row = detection_results_df.iloc[i]
            risk_score = float(detection_row.get('combined_risk_score', 0.5))
            confidence = float(detection_row.get('confidence', 0.5))
            risk_level = detection_row.get('risk_level', 'MEDIUM')
            
            
            attack_type = None
            if log.attack_type:
                attack_type = log.attack_type.value if hasattr(log.attack_type, 'value') else str(log.attack_type)
            elif risk_score > 0.7:
                
                attack_type = _infer_attack_type(log_dict, detection_row)
            
          
            explanation = _create_explanation(
                risk_score, 
                risk_level, 
                behavioral_result,
                detection_row
            )
            
           
            result = DetectionResult(
                log_id=log.session_id,
                timestamp=log.timestamp,
                risk_score=risk_score,
                attack_type=attack_type,
                confidence=confidence,
                features=features_df.iloc[i].to_dict(),
                explanation=explanation,
                action_taken="alert" if risk_score > 0.7 else "monitor"
            )
            
            results.append(result)
            
        except Exception as e:
            print(f" Error processing log {i}: {e}")
            continue
    
    return results

def _infer_attack_type(log_dict: Dict, detection_row: pd.Series) -> str:
    """Infer attack type based on features and scores"""
  
    if detection_row.get('sql_injection_indicator', 0) > 0:
        return "sql_injection"
    

    if detection_row.get('xss_indicator', 0) > 0:
        return "xss_attack"
    
  
    if detection_row.get('user_request_frequency', 0) > 50:
        if log_dict.get('endpoint', '').endswith('/login'):
            return "credential_stuffing"
        else:
            return "data_scraping"
    
    return "unknown_attack"

def _create_explanation(risk_score: float, risk_level: str, 
                       behavioral_result: Dict, detection_row: pd.Series) -> str:
    """Create human-readable explanation for the detection"""
    explanations = []
    
    
    explanations.append(f"Risk Level: {risk_level} (score: {risk_score:.2f})")
    
    
    if behavioral_result.get('suspicious_behavior'):
        behavior_score = behavioral_result.get('behavior_risk_score', 0)
        explanations.append(f"Behavioral anomaly detected (score: {behavior_score:.2f})")
        
        detected_anomalies = behavioral_result.get('detected_anomalies', {})
        for anomaly_type, is_detected in detected_anomalies.items():
            if is_detected:
                explanations.append(f"- {anomaly_type.replace('_', ' ').title()}")
    
    
    model_agreement = detection_row.get('model_agreement', 0)
    if model_agreement > 0:
        explanations.append(f"Model consensus: {model_agreement*100:.0f}%")
    
   
    if detection_row.get('sql_injection_indicator', 0) > 0:
        explanations.append("SQL injection patterns detected")
    
    if detection_row.get('xss_indicator', 0) > 0:
        explanations.append("XSS patterns detected")
    
    return " | ".join(explanations)

async def notify_websockets(message: Dict[str, Any]):
    """Send message to all WebSocket clients"""
    disconnected = []
    for connection in active_connections:
        try:
            await connection.send_json(message)
        except Exception:
            disconnected.append(connection)
    
    # Remove disconnected clients
    for connection in disconnected:
        active_connections.remove(connection)

if __name__ == "__main__":
    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)