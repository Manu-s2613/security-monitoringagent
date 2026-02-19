"""
AI-Based Cloud Security Monitoring - Flask Backend
Provides REST API and web interface for security dashboard
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import pandas as pd
import os
import requests as req
from datetime import datetime

# -------------------------------------------------
# Flask + Socket.IO Setup
# -------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder='../frontend/templates',
    static_folder="static"
)

socketio = SocketIO(app, cors_allowed_origins="*")

# -------------------------------------------------
# Dataset Paths
# -------------------------------------------------
CLOUD_LOGS_PATH = os.path.join(BASE_DIR, "..", "dataset", "cloud_logs.csv")
THREATS_PATH = os.path.join(BASE_DIR, "..", "dataset", "detected_threats.csv")

# -------------------------------------------------
# Data Loading
# -------------------------------------------------
def load_data():
    try:
        cloud_logs = pd.read_csv(CLOUD_LOGS_PATH)
    except Exception as e:
        print("ERROR loading cloud_logs:", e)
        cloud_logs = pd.DataFrame()

    try:
        threats = pd.read_csv(THREATS_PATH)
    except Exception as e:
        print("ERROR loading threats:", e)
        threats = pd.DataFrame()

    return cloud_logs, threats

# -------------------------------------------------
# Business Logic
# -------------------------------------------------
def get_user_summary():
    cloud_logs, threats = load_data()
    if cloud_logs.empty:
        return []

    user_stats = cloud_logs.groupby("user_id").agg({
        "login_count": "sum",
        "cpu_usage": "mean",
        "network_in": "mean",
        "network_out": "mean"
    }).reset_index()

    user_stats["cpu_usage"] = user_stats["cpu_usage"].round(2)
    user_stats["network_in"] = user_stats["network_in"].round(2)
    user_stats["network_out"] = user_stats["network_out"].round(2)

    if not threats.empty:
        threat_counts = threats.groupby("user_id").size().reset_index(name="threat_count")
        user_stats = user_stats.merge(threat_counts, on="user_id", how="left")

        risk_levels = threats.groupby("user_id")["risk_level"].apply(
            lambda x: "High" if "High" in x.values else
                      "Medium" if "Medium" in x.values else
                      "Low"
        ).reset_index()

        user_stats = user_stats.merge(risk_levels, on="user_id", how="left")
    else:
        user_stats["threat_count"] = 0
        user_stats["risk_level"] = "Normal"

    user_stats.fillna({"threat_count": 0, "risk_level": "Normal"}, inplace=True)
    return user_stats.to_dict("records")


def get_user_details(user_id):
    cloud_logs, threats = load_data()

    user_logs = cloud_logs[cloud_logs["user_id"] == user_id]
    user_threats = threats[threats["user_id"] == user_id]

    if user_logs.empty:
        return None

    highest_risk = "Normal"
    if not user_threats.empty:
        if "High" in user_threats["risk_level"].values:
            highest_risk = "High"
        elif "Medium" in user_threats["risk_level"].values:
            highest_risk = "Medium"
        elif "Low" in user_threats["risk_level"].values:
            highest_risk = "Low"

    return {
        "user_id": user_id,
        "total_logins": int(user_logs["login_count"].sum()),
        "avg_cpu_usage": round(user_logs["cpu_usage"].mean(), 2),
        "avg_network_in": round(user_logs["network_in"].mean(), 2),
        "avg_network_out": round(user_logs["network_out"].mean(), 2),
        "threat_count": len(user_threats),
        "highest_risk": highest_risk,
        "threats": user_threats.to_dict("records"),
        "activity_logs": user_logs.to_dict("records")
    }

# -------------------------------------------------
# Routes (HTML)
# -------------------------------------------------
@app.route("/")
@app.route("/admin")
def admin_dashboard():
    return render_template("admin_dashboard.html")

@app.route("/user/<user_id>")
def user_detail(user_id):
    user = get_user_details(user_id)
    if not user:
        return "User not found", 404
    return render_template("user_detail.html", user=user)

# -------------------------------------------------
# API Routes
# -------------------------------------------------
@app.route("/api/users")
def api_users():
    users = get_user_summary()
    return jsonify({"success": True, "users": users})

@app.route("/api/user/<user_id>")
def api_user(user_id):
    user = get_user_details(user_id)
    if not user:
        return jsonify({"success": False}), 404
    return jsonify({"success": True, "user": user})

@app.route("/api/statistics")
def api_statistics():
    cloud_logs, threats = load_data()
    return jsonify({
        "success": True,
        "total_users": len(cloud_logs["user_id"].unique()) if not cloud_logs.empty else 0,
        "total_threats": len(threats) if not threats.empty else 0,
        "threat_distribution": threats["attack_type"].value_counts().to_dict() if not threats.empty else {},
        "risk_distribution": threats["risk_level"].value_counts().to_dict() if not threats.empty else {}
    })

# -------------------------------------------------
# AI SOC Assistant (Ollama)
# -------------------------------------------------
@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    user_message = data.get("message", "")

    try:
        response = req.post("http://localhost:11434/api/generate", json={
            "model": "llama3",
            "prompt": (
                "You are an AI security analyst assistant for a cloud security monitoring system. "
                "Help analyze threats, explain attack types, and give security recommendations.\n\n"
                f"User: {user_message}\nAssistant:"
            ),
            "stream": False
        })
        reply = response.json()["response"]
    except Exception as e:
        reply = f"AI assistant error: {str(e)}"

    return jsonify({"reply": reply})

# -------------------------------------------------
# REAL-TIME SECURITY EVENTS (Socket.IO)
# -------------------------------------------------
def push_event(event):
    socketio.emit("security_event", event)

@app.route("/simulate/failed-login")
def simulate_failed_login():
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": "failed_login",
        "ip": "192.168.1.45",
        "user": "user_101",
        "severity": "medium",
        "message": "Multiple failed login attempts detected"
    }
    push_event(event)
    return jsonify({"status": "event sent"})

# -------------------------------------------------
# Main
# -------------------------------------------------
if __name__ == "__main__":
    print("🚀 Cloud Security Monitoring running")
    print("Dashboard → http://127.0.0.1:5000/admin")
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)