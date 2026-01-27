"""
Phishing Detection API - Main Entry Point
Run this script from the project root directory to start the API server
"""

import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    import uvicorn
    
    print("="*70)
    print("🛡️  Real-Time Phishing Detection API")
    print("="*70)
    print(f"📂 Project Root: {os.getcwd()}")
    print(f"🐍 Python: {sys.version.split()[0]}")
    print("="*70)
    print("\n🚀 Starting server...")
    print("📖 API Documentation: http://localhost:8000/docs")
    print("💚 Health Check: http://localhost:8000/health")
    print("\n⚠️  Press CTRL+C to stop\n")
    print("="*70 + "\n")
    
    uvicorn.run(
        "backend.api_gateway.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
