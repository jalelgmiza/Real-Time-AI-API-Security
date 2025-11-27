import uvicorn
import threading
import time
from generate_data import main as generate_data
from train_models import main as train_models
import webbrowser
import sys

def launch_dashboard():
    """Launch the web dashboard"""
    time.sleep(5)  
    webbrowser.open('http://localhost:8000')

if __name__ == "__main__":
    print(" API SENTINEL PRO - Starting Complete System...")
    print("=" * 60)
    
    try:
        print("\n STEP 1: Generating training data...")
        print("-" * 60)
        generate_data()
        
        print("\n STEP 2: Training ML models...")
        print("-" * 60)
        train_models()
        
        print("\n STEP 3: Starting web server...")
        print("-" * 60)
        print(" All models trained successfully!")
        print(" Dashboard will open at: http://localhost:8000")
        print(" Press CTRL+C to stop the server")
        print("=" * 60)
        
        
        threading.Thread(target=launch_dashboard, daemon=True).start()
        
        uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
        
    except KeyboardInterrupt:
        print("\n\n Server stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n Error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)