from waitress import serve
from app import app
import logging

if __name__ == "__main__":
    # Setup minimal production logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('waitress')
    logger.setLevel(logging.INFO)
    
    print("[+] SecOpsAI Production Web Server Initialized")
    print("[+] Bound to http://0.0.0.0:8080")
    print("[+] Using Waitress WSGI with 25 worker threads.")
    
    serve(app, host='0.0.0.0', port=8080, threads=25)
