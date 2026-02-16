
def create_event(event_type, ip, user, severity, message):
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "type": event_type,
        "ip": ip,
        "user": user,
        "severity": severity,
        "message": message
    }
