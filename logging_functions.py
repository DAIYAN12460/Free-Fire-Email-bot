# logging_functions.py
import json
import os
from datetime import datetime, timedelta

LOG_FILE = "user_logs.json"

def log_user_action(user_id, username, action, data=None, result="Success"):
    """Log user action to JSON file"""
    try:
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'w') as f:
                json.dump([], f)
        
        with open(LOG_FILE, 'r') as f:
            logs = json.load(f)
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "username": username,
            "action": action,
            "data": data or {},
            "result": result
        }
        logs.append(log_entry)
        
        # Keep only last 1000 logs
        if len(logs) > 1000:
            logs = logs[-1000:]
        
        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=2)
    except:
        pass

def get_user_logs(user_id, limit=50):
    """Get logs for a specific user"""
    try:
        if not os.path.exists(LOG_FILE):
            return []
        with open(LOG_FILE, 'r') as f:
            logs = json.load(f)
        user_logs = [log for log in logs if log.get("user_id") == user_id]
        return user_logs[-limit:]
    except:
        return []

def get_all_logs_since(days=1):
    """Get all logs from last N days"""
    try:
        if not os.path.exists(LOG_FILE):
            return []
        with open(LOG_FILE, 'r') as f:
            logs = json.load(f)
        cutoff = datetime.now() - timedelta(days=days)
        recent = []
        for log in logs:
            try:
                log_time = datetime.fromisoformat(log.get("timestamp", ""))
                if log_time > cutoff:
                    recent.append(log)
            except:
                pass
        return recent[-100:]
    except:
        return []