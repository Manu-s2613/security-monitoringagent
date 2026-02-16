"""
AI-Based Cloud Security Monitoring - Flask Backend
Provides REST API and web interface for security dashboard
"""

from flask import Flask, render_template, jsonify, request
import pandas as pd
import os
from datetime import datetime
import os
from flask import Flask, jsonify
from flask_socketio import SocketIO
from datetime import datetime

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")


app = Flask(__name__, 
            template_folder='../frontend/templates',
            static_folder='../static')



BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CLOUD_LOGS_PATH = os.path.join(BASE_DIR, "..", "dataset", "cloud_logs.csv")
THREATS_PATH = os.path.join(BASE_DIR, "..", "dataset", "detected_threats.csv")



def load_data():
    try:
        cloud_logs = pd.read_csv(CLOUD_LOGS_PATH)
        print("DEBUG: cloud_logs rows =", len(cloud_logs))
    except Exception as e:
        print("DEBUG ERROR reading cloud_logs:", e)
        cloud_logs = pd.DataFrame()

    try:
        threats = pd.read_csv(THREATS_PATH)
        print("DEBUG: threats rows =", len(threats))
    except Exception as e:
        print("DEBUG ERROR reading threats:", e)
        threats = pd.DataFrame()

    return cloud_logs, threats




def get_user_summary():
    """
    Generate summary statistics for all users
    Returns list of user summaries with threat counts and risk levels
    """
    cloud_logs, threats = load_data()
    
    if cloud_logs.empty:
        return []
    
    # Group cloud logs by user
    user_stats = cloud_logs.groupby('user_id').agg({
        'login_count': 'sum',
        'cpu_usage': 'mean',
        'network_in': 'mean',
        'network_out': 'mean'
    }).reset_index()
    
    # Count threats per user
    if not threats.empty:
        threat_counts = threats.groupby('user_id').size().reset_index(name='threat_count')
        user_stats = user_stats.merge(threat_counts, on='user_id', how='left')
        
        # Get highest risk level per user
        risk_levels = threats.groupby('user_id')['risk_level'].apply(
            lambda x: 'High' if 'High' in x.values else ('Medium' if 'Medium' in x.values else 'Low')
        ).reset_index()
        user_stats = user_stats.merge(risk_levels, on='user_id', how='left')
    else:
        user_stats['threat_count'] = 0
        user_stats['risk_level'] = 'Normal'
    
    # Fill missing values
    user_stats['threat_count'] = user_stats['threat_count'].fillna(0).astype(int)
    user_stats['risk_level'] = user_stats['risk_level'].fillna('Normal')
    
    # Round numerical values
    user_stats['cpu_usage'] = user_stats['cpu_usage'].round(2)
    user_stats['network_in'] = user_stats['network_in'].round(2)
    user_stats['network_out'] = user_stats['network_out'].round(2)
    
    # Sort by threat count (descending) then by risk level
    risk_order = {'High': 3, 'Medium': 2, 'Low': 1, 'Normal': 0}
    user_stats['risk_order'] = user_stats['risk_level'].map(risk_order)
    user_stats = user_stats.sort_values(['threat_count', 'risk_order'], ascending=[False, False])
    user_stats = user_stats.drop('risk_order', axis=1)
    
    return user_stats.to_dict('records')


def get_user_details(user_id):
    """
    Get detailed information for a specific user
    
    Args:
        user_id: User identifier
        
    Returns:
        Dictionary with user activity and threat details
    """
    cloud_logs, threats = load_data()
    
    # Filter data for specific user
    user_logs = cloud_logs[cloud_logs['user_id'] == user_id]
    user_threats = threats[threats['user_id'] == user_id]
    
    if user_logs.empty:
        return None
    
    # Calculate statistics
    total_logins = user_logs['login_count'].sum()
    avg_cpu = user_logs['cpu_usage'].mean()
    avg_network_in = user_logs['network_in'].mean()
    avg_network_out = user_logs['network_out'].mean()
    
    # Get threat information
    threat_list = []
    highest_risk = 'Normal'
    
    if not user_threats.empty:
        threat_list = user_threats.to_dict('records')
        
        # Determine highest risk level
        if 'High' in user_threats['risk_level'].values:
            highest_risk = 'High'
        elif 'Medium' in user_threats['risk_level'].values:
            highest_risk = 'Medium'
        elif 'Low' in user_threats['risk_level'].values:
            highest_risk = 'Low'
    
    return {
        'user_id': user_id,
        'total_logins': int(total_logins),
        'avg_cpu_usage': round(avg_cpu, 2),
        'avg_network_in': round(avg_network_in, 2),
        'avg_network_out': round(avg_network_out, 2),
        'threat_count': len(threat_list),
        'highest_risk': highest_risk,
        'threats': threat_list,
        'activity_logs': user_logs.to_dict('records')
    }


@app.route('/')
def index():
    """Redirect to admin dashboard"""
    return render_template('admin_dashboard.html')


@app.route('/admin')
def admin_dashboard():
    """Admin dashboard - shows all users and their threat status"""
    return render_template('admin_dashboard.html')


@app.route('/api/users')
def api_users():
    """API endpoint: Get all users summary"""
    users = get_user_summary()
    return jsonify({
        'success': True,
        'count': len(users),
        'users': users
    })


@app.route('/user/<user_id>')
def user_detail(user_id):
    """User detail page - shows specific user's activity and threats"""
    user_data = get_user_details(user_id)
    
    if user_data is None:
        return "User not found", 404
    
    return render_template('user_detail.html', user=user_data)


@app.route('/api/user/<user_id>')
def api_user_detail(user_id):
    """API endpoint: Get specific user details"""
    user_data = get_user_details(user_id)
    
    if user_data is None:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    return jsonify({
        'success': True,
        'user': user_data
    })


@app.route('/api/statistics')
def api_statistics():
    """API endpoint: Get overall system statistics"""
    cloud_logs, threats = load_data()
    
    total_users = len(cloud_logs['user_id'].unique()) if not cloud_logs.empty else 0
    total_threats = len(threats) if not threats.empty else 0
    
    # Threat distribution
    threat_distribution = {}
    if not threats.empty:
        threat_distribution = threats['attack_type'].value_counts().to_dict()
    
    # Risk distribution
    risk_distribution = {}
    if not threats.empty:
        risk_distribution = threats['risk_level'].value_counts().to_dict()
    
    return jsonify({
        'success': True,
        'total_users': total_users,
        'total_threats': total_threats,
        'threat_distribution': threat_distribution,
        'risk_distribution': risk_distribution
    })


@app.route('/api/refresh')
def api_refresh():
    """API endpoint: Trigger ML model re-run"""
    try:
        # This would trigger the ML pipeline in production
        # For now, just return success
        return jsonify({
            'success': True,
            'message': 'Data refresh triggered',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    return jsonify({'success': False, 'error': 'Internal server error'}), 500


if __name__ == '__main__':
    print("=" * 60)
    print("🚀 AI-Based Cloud Security Monitoring System")
    print("=" * 60)
    print("Starting Flask server...")
    print("Dashboard URL: http://127.0.0.1:5000")
    print("=" * 60)
    print()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
def push_event(event):
    socketio.emit("security_event", event)
