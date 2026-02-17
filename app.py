#!/usr/bin/env python3
import sys
import os
import time
import subprocess
import threading
import queue
import tempfile
import re
import random
import json
import math
import asyncio
import string
import secrets
from datetime import datetime, timedelta
from flask import Flask, send_from_directory, request, jsonify, render_template, abort, flash, redirect, url_for
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename

# Import GPIO and Serial modules with fallback
try:
    import lgpio
    RELAY_PIN = 26
except Exception as e:
    print(f"lgpio import failed: {e}")
    lgpio = None
    RELAY_PIN = None

try:
    import serial
    from serial.tools import list_ports
except Exception as e:
    serial = None
    list_ports = None

import eventlet
eventlet.monkey_patch()

# Import database models
from models import db, bcrypt, User, Experiment, Booking, Session, Device, OTAUpdate, PasswordResetToken, DeviceMetric, SystemLog

# Import configuration
from config import config

# Import UPS monitoring
try:
    import dfrobot_ups
    UPS_AVAILABLE = True
except ImportError:
    UPS_AVAILABLE = False

# System monitoring
import psutil

# Lab Pi communication
import requests
import threading
import time
from datetime import datetime

# ---------- CONFIG ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
DEFAULT_FW_DIR = os.path.join(BASE_DIR, 'default_fw')
SOP_DIR = os.path.join(BASE_DIR, 'static')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DEFAULT_FW_DIR, exist_ok=True)
os.makedirs(SOP_DIR, exist_ok=True)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'devkey'  # In production, use environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'vlab.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-app-password'
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'

socketio = SocketIO(app, async_mode='eventlet')
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
mail = Mail(app)

# Initialize database
db.init_app(app)
bcrypt.init_app(app)

with app.app_context():
    db.create_all()
    # Create default admin user if not exists
    if not User.query.filter_by(email='admin@vlab.edu').first():
        admin = User(
            email='admin@vlab.edu',
            full_name='Administrator',
            is_admin=True,
            active=True
        )
        admin.password = 'Admin@123'
        db.session.add(admin)
        db.session.commit()
    
    # Create default experiments if not exists
    if not Experiment.query.first():
        experiments = [
            {
                'name': 'DC Motor Speed Control',
                'description': 'Control DC motor speed using PWM with real-time RPM feedback. Ensure stable, precise, and reliable motor performance.',
                'max_duration': 60,
                'price': 0.0
            },
            {
                'name': 'Temperature & Humidity Monitoring',
                'description': 'Interface with a DHT sensor, read environmental data, and log/visualize the readings on a real-time data chart.',
                'max_duration': 60,
                'price': 0.0
            },
            {
                'name': 'Stepper Motor Control',
                'description': 'Implement precise sequence control logic to manage angular rotation, speed, and direction of a stepper motor.',
                'max_duration': 60,
                'price': 0.0
            }
        ]
        for exp in experiments:
            experiment = Experiment(**exp)
            db.session.add(experiment)
        db.session.commit()

# Global active sessions for authorization
active_sessions = {}

serial_lock = threading.Lock()
ser = None
ser_stop = threading.Event()
data_generator_thread = None

# ---------- RELAY CONTROL ----------
gpio_handle = None

def init_gpio():
    global gpio_handle
    if lgpio is None or RELAY_PIN is None:
        return False
    try:
        if gpio_handle is None:
            gpio_handle = lgpio.gpiochip_open(0)
            lgpio.gpio_claim_output(gpio_handle, RELAY_PIN)
        return True
    except Exception as e:
        print(f"Error initializing GPIO: {e}")
        gpio_handle = None
        return False

def relay_on():
    if not init_gpio():
        return False
    try:
        lgpio.gpio_write(gpio_handle, RELAY_PIN, 0)
        print("Relay ON")
        return True
    except Exception as e:
        print(f"Error turning relay ON: {e}")
        return False

def relay_off():
    if not init_gpio():
        return False
    try:
        lgpio.gpio_write(gpio_handle, RELAY_PIN, 1)
        print("Relay OFF")
        return True
    except Exception as e:
        print(f"Error turning relay OFF: {e}")
        return False

# ---------- UTIL FUNCTIONS ----------
def list_serial_ports():
    if list_ports is None:
        return []
    return [p.device for p in list_ports.comports()]

def generate_session_key():
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

def send_email(to, subject, template):
    try:
        msg = Message(subject, recipients=[to])
        msg.html = template
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

# ---------- USER AUTHENTICATION ----------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email.lower()).first()
        
        if user and user.active and user.check_password(password):
            login_user(user)
            user.last_login_at = datetime.utcnow()
            user.last_login_ip = request.remote_addr
            db.session.commit()
            
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('index'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form['email']
        full_name = request.form['full_name']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if User.query.filter_by(email=email.lower()).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('signup'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('signup'))
        
        if not User.validate_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character', 'danger')
            return redirect(url_for('signup'))
        
        user = User(
            email=email.lower(),
            full_name=full_name,
            active=True
        )
        user.password = password
        db.session.add(user)
        db.session.commit()
        
        flash('Your account has been created! You can now log in', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email.lower()).first()
        
        if user:
            token = secrets.token_urlsafe(32)
            reset_token = PasswordResetToken(user.id, token)
            db.session.add(reset_token)
            db.session.commit()
            
            reset_url = url_for('reset_password', token=token, _external=True)
            subject = 'Reset Your Password'
            template = f'''
                <h1>Password Reset Request</h1>
                <p>Click the link below to reset your password:</p>
                <a href="{reset_url}">Reset Password</a>
                <p>This link will expire in 1 hour.</p>
            '''
            
            if send_email(user.email, subject, template):
                flash('Password reset email sent. Check your inbox.', 'success')
            else:
                flash('Failed to send reset email', 'danger')
        else:
            flash('Email not registered', 'danger')
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    
    if not reset_token or reset_token.is_expired():
        flash('Invalid or expired reset token', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        if not User.validate_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        user = User.query.get(reset_token.user_id)
        user.password = password
        db.session.delete(reset_token)
        db.session.commit()
        
        flash('Your password has been reset', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

# ---------- ADMIN DASHBOARD ----------
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)
    
    # Update session statuses
    now = datetime.now()
    active_sessions_db = Session.query.filter_by(status='ACTIVE').all()
    for session in active_sessions_db:
        if now > session.end_time:
            session.status = 'EXPIRED'
    
    db.session.commit()
    
    users = User.query.all()
    experiments = Experiment.query.all()
    bookings = Booking.query.all()
    devices = Device.query.all()
    sessions = Session.query.all()
    
    return render_template('admin/dashboard.html', 
                         users=users, 
                         experiments=experiments, 
                         bookings=bookings, 
                         devices=devices,
                         sessions=sessions)

@app.route('/admin/devices', methods=['GET', 'POST'])
@login_required
def manage_devices():
    if not current_user.is_admin:
        abort(403)
    
    if request.method == 'POST':
        device = Device(
            mac_address=request.form['mac_address'],
            ip_address=request.form['ip_address'],
            device_name=request.form['device_name'],
            device_type=request.form['device_type'],
            location=request.form['location'],
            status='ONLINE',
            last_seen=datetime.utcnow()
        )
        db.session.add(device)
        db.session.commit()
        flash('Device added successfully', 'success')
        return redirect(url_for('manage_devices'))
    
    devices = Device.query.all()
    return render_template('admin/devices.html', devices=devices)

@app.route('/admin/devices/delete/<int:device_id>')
@login_required
def delete_device(device_id):
    if not current_user.is_admin:
        abort(403)
    
    device = Device.query.get(device_id)
    if device:
        db.session.delete(device)
        db.session.commit()
        flash('Device deleted successfully', 'success')
    else:
        flash('Device not found', 'danger')
    
    return redirect(url_for('manage_devices'))

@app.route('/admin/devices/toggle_maintenance/<int:device_id>', methods=['POST'])
@login_required
def toggle_maintenance_mode(device_id):
    if not current_user.is_admin:
        abort(403)
    
    device = Device.query.get(device_id)
    if device:
        device.maintenance_mode = not device.maintenance_mode
        device.status = 'MAINTENANCE' if device.maintenance_mode else 'ONLINE'
        db.session.commit()
        flash('Maintenance mode toggled successfully', 'success')
    else:
        flash('Device not found', 'danger')
    
    return redirect(url_for('manage_devices'))

@app.route('/admin/devices/restart/<int:device_id>', methods=['POST'])
@login_required
def restart_device(device_id):
    if not current_user.is_admin:
        abort(403)
    
    device = Device.query.get(device_id)
    if device:
        # In a real implementation, you would send a restart command to the device
        # For now, we'll just log it and update the last seen time
        log_entry = SystemLog(
            level='INFO',
            category='SYSTEM',
            message=f'Device restart initiated: {device.device_name}',
            device_id=device.id,
            user_id=current_user.id
        )
        db.session.add(log_entry)
        device.last_seen = datetime.utcnow()
        db.session.commit()
        flash('Device restart initiated', 'success')
    else:
        flash('Device not found', 'danger')
    
    return redirect(url_for('manage_devices'))

@app.route('/admin/devices/reboot/<int:device_id>', methods=['POST'])
@login_required
def reboot_device(device_id):
    if not current_user.is_admin:
        abort(403)
    
    device = Device.query.get(device_id)
    if device:
        # In a real implementation, you would send a reboot command to the device
        # For now, we'll just log it and update the last seen time
        log_entry = SystemLog(
            level='INFO',
            category='SYSTEM',
            message=f'Device reboot initiated: {device.device_name}',
            device_id=device.id,
            user_id=current_user.id
        )
        db.session.add(log_entry)
        device.last_seen = datetime.utcnow()
        db.session.commit()
        flash('Device reboot initiated', 'success')
    else:
        flash('Device not found', 'danger')
    
    return redirect(url_for('manage_devices'))

@app.route('/admin/devices/metrics/<int:device_id>')
@login_required
def get_device_metrics(device_id):
    if not current_user.is_admin:
        abort(403)
    
    device = Device.query.get(device_id)
    if not device:
        abort(404)
    
    # Get last 24 hours of metrics
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24)
    
    metrics = DeviceMetric.query.filter(
        DeviceMetric.device_id == device_id,
        DeviceMetric.timestamp >= start_time,
        DeviceMetric.timestamp <= end_time
    ).order_by(DeviceMetric.timestamp).all()
    
    return jsonify({
        'device': {
            'id': device.id,
            'name': device.device_name,
            'status': device.status
        },
        'metrics': [{
            'timestamp': metric.timestamp.isoformat(),
            'cpu_usage': metric.cpu_usage,
            'ram_usage': metric.ram_usage,
            'temperature': metric.temperature,
            'battery_level': metric.battery_level,
            'battery_voltage': metric.battery_voltage,
            'ac_status': metric.ac_status,
            'charging_status': metric.charging_status
        } for metric in metrics]
    })

@app.route('/admin/logs')
@login_required
def manage_logs():
    if not current_user.is_admin:
        abort(403)
    
    category = request.args.get('category', 'ALL')
    level = request.args.get('level', 'ALL')
    device_id = request.args.get('device_id', None)
    user_id = request.args.get('user_id', None)
    
    # Build query
    logs_query = SystemLog.query
    
    if category != 'ALL':
        logs_query = logs_query.filter(SystemLog.category == category)
    
    if level != 'ALL':
        logs_query = logs_query.filter(SystemLog.level == level)
    
    if device_id:
        logs_query = logs_query.filter(SystemLog.device_id == int(device_id))
    
    if user_id:
        logs_query = logs_query.filter(SystemLog.user_id == int(user_id))
    
    logs = logs_query.order_by(SystemLog.timestamp.desc()).limit(1000).all()
    
    # Add sample logs if no logs exist
    if not logs:
        from datetime import datetime, timedelta
        
        # Sample log entries
        sample_logs = [
            {
                'level': 'INFO',
                'category': 'SYSTEM',
                'message': 'System startup complete',
                'timestamp': datetime.now() - timedelta(minutes=5)
            },
            {
                'level': 'INFO',
                'category': 'SYSTEM',
                'message': 'Device Raspberry Pi 4 (ID: 1) connected',
                'timestamp': datetime.now() - timedelta(minutes=3)
            },
            {
                'level': 'INFO',
                'category': 'EXPERIMENT',
                'message': 'User John Doe started DC Motor Speed Control experiment',
                'timestamp': datetime.now() - timedelta(minutes=2)
            },
            {
                'level': 'WARNING',
                'category': 'SYSTEM',
                'message': 'High CPU usage detected (85%)',
                'timestamp': datetime.now() - timedelta(minutes=1)
            },
            {
                'level': 'INFO',
                'category': 'SSH',
                'message': 'Admin logged in from 192.168.1.100',
                'timestamp': datetime.now()
            },
            {
                'level': 'INFO',
                'category': 'SYSTEM',
                'message': 'UPS battery at 75%',
                'timestamp': datetime.now() - timedelta(hours=1)
            },
            {
                'level': 'ERROR',
                'category': 'EXPERIMENT',
                'message': 'Failed to start Temperature & Humidity Monitoring experiment',
                'timestamp': datetime.now() - timedelta(hours=2)
            }
        ]
        
        # Add sample logs to database
        for log in sample_logs:
            system_log = SystemLog(
                level=log['level'],
                category=log['category'],
                message=log['message'],
                timestamp=log['timestamp'],
                device_id=1 if log['category'] in ['SYSTEM', 'EXPERIMENT'] else None,
                user_id=1 if log['category'] in ['EXPERIMENT', 'SSH'] else None
            )
            db.session.add(system_log)
        
        db.session.commit()
        
        # Refresh logs
        logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(1000).all()
    
    devices = Device.query.all()
    users = User.query.all()
    
    return render_template('admin/logs.html', 
                         logs=logs,
                         devices=devices,
                         users=users,
                         selected_category=category,
                         selected_level=level,
                         selected_device=device_id,
                         selected_user=user_id)

@app.route('/admin/logs/download')
@login_required
def download_logs():
    if not current_user.is_admin:
        abort(403)
    
    category = request.args.get('category', 'ALL')
    level = request.args.get('level', 'ALL')
    device_id = request.args.get('device_id', None)
    user_id = request.args.get('user_id', None)
    
    # Build query
    logs_query = SystemLog.query
    
    if category != 'ALL':
        logs_query = logs_query.filter(SystemLog.category == category)
    
    if level != 'ALL':
        logs_query = logs_query.filter(SystemLog.level == level)
    
    if device_id:
        logs_query = logs_query.filter(SystemLog.device_id == int(device_id))
    
    if user_id:
        logs_query = logs_query.filter(SystemLog.user_id == int(user_id))
    
    logs = logs_query.order_by(SystemLog.timestamp.desc()).all()
    
    # Generate CSV content
    import csv
    from io import StringIO
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Level', 'Category', 'Device', 'User', 'Message'])
    
    for log in logs:
        device_name = log.device.device_name if log.device else '-'
        user_name = log.user.full_name if log.user else '-'
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.level,
            log.category,
            device_name,
            user_name,
            log.message
        ])
    
    output.seek(0)
    
    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="system_logs.csv"'
    }

@app.route('/admin/analytics')
@login_required
def view_analytics():
    if not current_user.is_admin:
        abort(403)
    
    # Calculate analytics
    now = datetime.utcnow()
    
    # Devices by status
    online_devices = Device.query.filter_by(status='ONLINE').count()
    offline_devices = Device.query.filter_by(status='OFFLINE').count()
    maintenance_devices = Device.query.filter_by(status='MAINTENANCE').count()
    
    # Users by activity
    active_users = User.query.filter_by(active=True).count()
    total_users = User.query.count()
    
    # Experiments by activity
    active_experiments = Experiment.query.filter_by(active=True).count()
    total_experiments = Experiment.query.count()
    
    # Sessions by status
    active_sessions = Session.query.filter_by(status='ACTIVE').count()
    total_sessions = Session.query.count()
    
    # Bookings by status
    active_bookings = Booking.query.filter_by(status='ACTIVE').count()
    total_bookings = Booking.query.count()
    
    # Session analytics (active, recent, upcoming, total)
    # Active sessions (currently running)
    active_sessions_count = Session.query.filter_by(status='ACTIVE').count()
    
    # Recent sessions (last 7 days)
    seven_days_ago = now - timedelta(days=7)
    recent_sessions_count = Session.query.filter(
        Session.start_time >= seven_days_ago,
        Session.status.in_(['ACTIVE', 'EXPIRED', 'TERMINATED'])
    ).count()
    
    # Upcoming sessions (future bookings that will have sessions)
    upcoming_sessions_count = Booking.query.filter(
        Booking.start_time > now,
        Booking.status == 'UPCOMING'
    ).count()
    
    # Total sessions (all time)
    total_sessions_count = Session.query.count()
    
    # Get real data for charts (last 7 days)
    chart_data = []
    for i in range(6, -1, -1):
        day = now - timedelta(days=i)
        start_of_day = day.replace(hour=0, minute=0, second=0, microsecond=0)
        end_of_day = day.replace(hour=23, minute=59, second=59, microsecond=999999)
        
        # Device status counts for each day
        day_online = Device.query.filter(
            Device.last_seen >= start_of_day,
            Device.last_seen <= end_of_day,
            Device.status == 'ONLINE'
        ).count()
        
        day_offline = Device.query.filter(
            Device.last_seen >= start_of_day,
            Device.last_seen <= end_of_day,
            Device.status == 'OFFLINE'
        ).count()
        
        day_maintenance = Device.query.filter(
            Device.last_seen >= start_of_day,
            Device.last_seen <= end_of_day,
            Device.status == 'MAINTENANCE'
        ).count()
        
        # User activity for each day
        day_active_users = User.query.filter(
            User.last_login_at >= start_of_day,
            User.last_login_at <= end_of_day
        ).count()
        
        # New users for each day
        day_new_users = User.query.filter(
            User.created_at >= start_of_day,
            User.created_at <= end_of_day
        ).count()
        
        chart_data.append({
            'date': day.strftime('%a'),
            'online_devices': day_online,
            'offline_devices': day_offline,
            'maintenance_devices': day_maintenance,
            'active_users': day_active_users,
            'new_users': day_new_users
        })
    
    return render_template('admin/analytics.html',
                         online_devices=online_devices,
                         offline_devices=offline_devices,
                         maintenance_devices=maintenance_devices,
                         active_users=active_users,
                         total_users=total_users,
                         active_experiments=active_experiments,
                         total_experiments=total_experiments,
                         active_sessions=active_sessions,
                         total_sessions=total_sessions,
                         active_bookings=active_bookings,
                         total_bookings=total_bookings,
                         active_sessions_count=active_sessions_count,
                         recent_sessions_count=recent_sessions_count,
                         upcoming_sessions_count=upcoming_sessions_count,
                         total_sessions_count=total_sessions_count,
                         chart_data=chart_data)

# ---------- SYSTEM MONITORING ----------
def update_system_metrics():
    """Background task to update system metrics"""
    while True:
        try:
            with app.app_context():
                # Get system metrics
                cpu_usage = psutil.cpu_percent()
                ram_usage = psutil.virtual_memory().percent
                temperature = None
                
                # Try to get temperature (platform specific)
                if hasattr(psutil, 'sensors_temperatures'):
                    try:
                        temps = psutil.sensors_temperatures()
                        if 'cpu_thermal' in temps:
                            temperature = temps['cpu_thermal'][0].current
                        elif 'coretemp' in temps:
                            temperature = temps['coretemp'][0].current
                    except:
                        pass
                
                # Get UPS metrics
                battery_level = None
                battery_voltage = None
                ac_status = None
                charging_status = None
                
                if UPS_AVAILABLE:
                    try:
                        battery_level = dfrobot_ups.read_soc()
                        battery_voltage = dfrobot_ups.read_voltage()
                        ac_status_str = dfrobot_ups.ac_status()
                        ac_status = ac_status_str == "AC_CONNECTED"
                        charging_status_str = dfrobot_ups.charging_status(ac_status_str, battery_voltage)
                        charging_status = charging_status_str == "CHARGING"
                    except:
                        pass
                
                # Update main device metrics (assuming single device for now)
                device = Device.query.first()
                if device:
                    device.cpu_usage = cpu_usage
                    device.ram_usage = ram_usage
                    device.temperature = temperature
                    device.battery_level = battery_level
                    device.battery_voltage = battery_voltage
                    device.ac_status = ac_status
                    device.charging_status = charging_status
                    device.last_seen = datetime.utcnow()
                    
                    # Create metric history entry
                    metric = DeviceMetric(
                        device_id=device.id,
                        cpu_usage=cpu_usage,
                        ram_usage=ram_usage,
                        temperature=temperature,
                        battery_level=battery_level,
                        battery_voltage=battery_voltage,
                        ac_status=ac_status,
                        charging_status=charging_status
                    )
                    db.session.add(metric)
                    db.session.commit()
            
            # Sleep for 60 seconds before next update
            time.sleep(60)
            
        except Exception as e:
            print(f"Error updating system metrics: {e}")
            time.sleep(60)

# Start background task for system monitoring
def start_monitoring_thread():
    if not hasattr(app, 'metric_thread'):
        app.metric_thread = threading.Thread(target=update_system_metrics, daemon=True)
        app.metric_thread.start()
        print("✅ System metrics monitoring started")

# Run the monitoring thread when the application starts
with app.app_context():
    start_monitoring_thread()

@app.route('/admin/experiments', methods=['GET', 'POST'])
@login_required
def manage_experiments():
    if not current_user.is_admin:
        abort(403)
    
    if request.method == 'POST':
        experiment = Experiment(
            name=request.form['name'],
            description=request.form['description'],
            max_duration=int(request.form['max_duration']),
            price=float(request.form['price'])
        )
        db.session.add(experiment)
        db.session.commit()
        flash('Experiment added successfully', 'success')
        return redirect(url_for('manage_experiments'))
    
    experiments = Experiment.query.all()
    return render_template('admin/experiments.html', experiments=experiments)

@app.route('/admin/experiments/delete/<int:exp_id>')
@login_required
def delete_experiment(exp_id):
    if not current_user.is_admin:
        abort(403)
    
    experiment = Experiment.query.get(exp_id)
    if experiment:
        db.session.delete(experiment)
        db.session.commit()
        flash('Experiment deleted successfully', 'success')
    else:
        flash('Experiment not found', 'danger')
    
    return redirect(url_for('manage_experiments'))

@app.route('/admin/users')
@login_required
def manage_users():
    if not current_user.is_admin:
        abort(403)
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get(user_id)
    if user and not user.is_admin:  # Prevent deleting admin
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully', 'success')
    else:
        flash('User not found or cannot be deleted', 'danger')
    
    return redirect(url_for('manage_users'))

@app.route('/admin/bookings')
@login_required
def manage_bookings():
    if not current_user.is_admin:
        abort(403)
    
    bookings = Booking.query.all()
    return render_template('admin/bookings.html', bookings=bookings)

@app.route('/admin/bookings/delete/<int:booking_id>')
@login_required
def delete_booking(booking_id):
    if not current_user.is_admin:
        abort(403)
    
    booking = Booking.query.get(booking_id)
    if booking:
        db.session.delete(booking)
        db.session.commit()
        flash('Booking deleted successfully', 'success')
    else:
        flash('Booking not found', 'danger')
    
    return redirect(url_for('manage_bookings'))

@app.route('/admin/sessions')
@login_required
def manage_sessions():
    if not current_user.is_admin:
        abort(403)
    
    # Update session statuses
    now = datetime.now()
    active_sessions_db = Session.query.filter_by(status='ACTIVE').all()
    for session in active_sessions_db:
        if now > session.end_time:
            session.status = 'EXPIRED'
    
    db.session.commit()
    
    sessions = Session.query.all()
    return render_template('admin/sessions.html', sessions=sessions)

@app.route('/admin/sessions/delete/<int:session_id>')
@login_required
def delete_session(session_id):
    if not current_user.is_admin:
        abort(403)
    
    session = Session.query.get(session_id)
    if session:
        db.session.delete(session)
        db.session.commit()
        flash('Session deleted successfully', 'success')
    else:
        flash('Session not found', 'danger')
    
    return redirect(url_for('manage_sessions'))

@app.route('/admin/booking/<int:booking_id>')
@login_required
def view_booking(booking_id):
    if not current_user.is_admin:
        abort(403)
    
    booking = Booking.query.get(booking_id)
    if not booking:
        abort(404)
    
    return render_template('admin/view_booking.html', booking=booking)

@app.route('/admin/session/<int:session_id>')
@login_required
def view_session(session_id):
    if not current_user.is_admin:
        abort(403)
    
    session = Session.query.get(session_id)
    if not session:
        abort(404)
    
    return render_template('admin/view_session.html', session=session)

# ---------- MAIN ROUTES ----------
@app.route('/')
def index():
    experiments = Experiment.query.filter_by(active=True).all()
    bookings = []
    if current_user.is_authenticated:
        bookings = Booking.query.filter_by(user_id=current_user.id).order_by(Booking.start_time.desc()).all()
        
        # Update booking statuses
        now = datetime.now()
        for booking in bookings:
            if booking.status == 'UPCOMING':
                if now < booking.start_time:
                    booking.status = 'UPCOMING'
                elif booking.start_time <= now <= booking.end_time:
                    booking.status = 'ACTIVE'
                elif now > booking.end_time:
                    booking.status = 'EXPIRED'
            elif booking.status == 'ACTIVE':
                if now > booking.end_time:
                    booking.status = 'EXPIRED'
            elif booking.status == 'IN_PROGRESS':
                # Calculate duration from start and end time
                duration = (booking.end_time - booking.start_time).total_seconds() // 60
                if booking.started_at and now > booking.started_at + timedelta(minutes=duration):
                    booking.status = 'COMPLETED'
                    booking.completed_at = datetime.now()
        
        # Update session statuses
        active_sessions_db = Session.query.filter_by(status='ACTIVE').all()
        for session in active_sessions_db:
            if now > session.end_time:
                session.status = 'EXPIRED'
        
        db.session.commit()
    
    return render_template('homepage.html', experiments=experiments, bookings=bookings)

@app.route('/experiment')
@login_required
def experiment():
    session_key = request.args.get('key')
    
    if not session_key:
        return render_template('expired_session.html')
    
    # First check if there's a booking with this session key
    booking = Booking.query.filter_by(session_key=session_key).first()
    
    if not booking:
        return render_template('expired_session.html')
    
    # Check if user owns the booking
    if booking.user_id != current_user.id:
        return render_template('expired_session.html')
    
    # Check if booking is active (using naive datetime for simplicity)
    now = datetime.now()
    if not (booking.start_time <= now <= booking.end_time):
        return render_template('expired_session.html')
    
    # Check if there's a session entry, create if not
    session = Session.query.filter_by(session_key=session_key).first()
    if not session:
        session = Session(
            booking_id=booking.id,
            user_id=current_user.id,
            session_key=booking.session_key,
            duration=(booking.end_time - booking.start_time).total_seconds() // 60,
            end_time=booking.end_time,
            ip_address=request.remote_addr,
            status='ACTIVE'
        )
        db.session.add(session)
        booking.status = 'IN_PROGRESS'
        db.session.commit()
    
    # Add to active sessions
    active_sessions[session_key] = {
        'start_time': time.time(),
        'duration': session.duration,
        'expires_at': session.end_time.timestamp()
    }
    
    duration = session.duration
    session_end_time = int(session.end_time.timestamp() * 1000)
    return render_template('index.html', session_duration=duration, session_end_time=session_end_time)

@app.route('/add_session', methods=['POST'])
@login_required
def add_session():
    data = request.get_json()
    session_key = data.get('session_key')
    duration = data.get('duration', 5)
    
    if session_key:
        active_sessions[session_key] = {
            'start_time': time.time(),
            'duration': duration,
            'expires_at': time.time() + (duration * 60)
        }
    
    return jsonify({'status': 'added'})

@app.route('/remove_session', methods=['POST'])
@login_required
def remove_session():
    data = request.get_json()
    session_key = data.get('session_key')
    if session_key in active_sessions:
        del active_sessions[session_key]
        relay_off()
    return jsonify({'status': 'removed'})

@app.route('/toggle_relay', methods=['POST'])
@login_required
def toggle_relay():
    data = request.get_json()
    state = data.get('state')
    session_key = data.get('session_key')
    
    # Check if session is valid
    if session_key not in active_sessions:
        return jsonify({'status': 'error', 'message': 'Invalid session'}), 400
    
    if state == 'on':
        success = relay_on()
        return jsonify({'status': 'on' if success else 'error'})
    elif state == 'off':
        success = relay_off()
        return jsonify({'status': 'off' if success else 'error'})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid state'}), 400

@app.route('/chart')
@login_required
def chart():
    session_key = request.args.get('key')
    if not session_key:
        return render_template('expired_session.html')
    
    # Check if session is valid (either in active_sessions or in database)
    session_valid = False
    
    # First check active sessions dictionary
    if session_key in active_sessions:
        session_valid = True
    else:
        # Check database for active session
        booking = Booking.query.filter_by(session_key=session_key).first()
        if booking:
            # Check if booking is active
            now = datetime.now()
            if booking.start_time <= now <= booking.end_time:
                session_valid = True
                # Add to active sessions if not already present
                active_sessions[session_key] = {
                    'start_time': time.time(),
                    'duration': (booking.end_time - booking.start_time).total_seconds() // 60,
                    'expires_at': booking.end_time.timestamp()
                }
    
    if not session_valid:
        return render_template('expired_session.html')
    
    return render_template('chart.html')

@app.route('/camera')
@login_required
def camera():
    session_key = request.args.get('key')
    if not session_key:
        return render_template('expired_session.html')
    
    # Check if session is valid (either in active_sessions or in database)
    session_valid = False
    
    # First check active sessions dictionary
    if session_key in active_sessions:
        session_valid = True
    else:
        # Check database for active session
        booking = Booking.query.filter_by(session_key=session_key).first()
        if booking:
            # Check if booking is active
            now = datetime.now()
            if booking.start_time <= now <= booking.end_time:
                session_valid = True
                # Add to active sessions if not already present
                active_sessions[session_key] = {
                    'start_time': time.time(),
                    'duration': (booking.end_time - booking.start_time).total_seconds() // 60,
                    'expires_at': booking.end_time.timestamp()
                }
    
    if not session_valid:
        return render_template('expired_session.html')
    
    return render_template('camera.html')

@app.route('/ports')
@login_required
def ports_rest():
    return jsonify({'ports': list_serial_ports()})

# ---------- BOOKING SYSTEM ----------
@app.route('/book/<int:exp_id>', methods=['GET', 'POST'])
@login_required
def book_experiment(exp_id):
    experiment = Experiment.query.get(exp_id)
    if not experiment or not experiment.active:
        flash('Experiment not available', 'danger')
        return redirect(url_for('index'))
    
    # Get available Lab Pis for this experiment
    available_devices = Device.query.filter_by(status='ONLINE', maintenance_mode=False, current_booking_id=None).all()
    experiment_devices = []
    for device in available_devices:
        if device.get_experiment_capabilities() and exp_id in device.get_experiment_capabilities():
            experiment_devices.append(device)
    
    if request.method == 'POST':
        print("DEBUG: Booking form submitted")
        print(f"DEBUG: Form data: {request.form}")
        
        slot_date = request.form['slotDate']
        slot_time = request.form['slotTime']
        duration = int(request.form['duration'])
        device_id = request.form.get('device_id', type=int)
        
        if duration > experiment.max_duration:
            flash(f'Maximum duration for this experiment is {experiment.max_duration} minutes', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        
        # Parse date and time - use naive datetime (local time) for simplicity
        try:
            start_time = datetime.strptime(f"{slot_date} {slot_time}", "%Y-%m-%d %H:%M")
            end_time = start_time + timedelta(minutes=duration)
            print(f"DEBUG: Parsed start time: {start_time}, end time: {end_time}")
        except ValueError as e:
            print(f"DEBUG: Date parsing error: {e}")
            flash('Invalid date or time format', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        
        # Check if slot is available
        overlapping_bookings = Booking.query.filter(
            Booking.experiment_id == exp_id,
            Booking.status.notin_(['CANCELLED', 'EXPIRED']),
            ((Booking.start_time < end_time) & (Booking.end_time > start_time))
        ).count()
        
        print(f"DEBUG: Overlapping bookings: {overlapping_bookings}")
        
        if overlapping_bookings > 0:
            flash('This slot is already booked. Please select another time.', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        
        # Create booking
        session_key = generate_session_key()
        booking = Booking(
            user_id=current_user.id,
            experiment_id=exp_id,
            start_time=start_time,
            end_time=end_time,
            status='UPCOMING',
            session_key=session_key
        )
        db.session.add(booking)
        db.session.commit()
        
        # Assign a Lab Pi to the booking if selected
        if device_id:
            device = Device.query.get(device_id)
            if device and device.is_available():
                device.current_booking_id = booking.id
                device.status = 'BUSY'
                db.session.commit()
                
                log_entry = SystemLog(
                    level='INFO',
                    category='EXPERIMENT',
                    message=f"Lab Pi '{device.device_name}' assigned to booking #{booking.id}",
                    device_id=device.id,
                    user_id=current_user.id
                )
                db.session.add(log_entry)
                db.session.commit()
        
        print(f"DEBUG: Booking created successfully: {booking}")
        print(f"DEBUG: Session key: {session_key}")
        
        # Send confirmation email
        subject = 'Booking Confirmed'
        template = f'''
            <h1>Booking Confirmed!</h1>
            <p>Your booking for {experiment.name} has been confirmed.</p>
            <p><strong>Date:</strong> {slot_date}</p>
            <p><strong>Time:</strong> {slot_time}</p>
            <p><strong>Duration:</strong> {duration} minutes</p>
            <p><strong>Session Key:</strong> {session_key}</p>
            {'<p><strong>Lab Pi:</strong> ' + (Device.query.get(device_id).device_name if device_id else 'Auto-assigned') + '</p>' if device_id else '<p><strong>Lab Pi:</strong> Auto-assigned</p>'}
            <p>You will receive a reminder email 30 minutes before your session starts.</p>
        '''
        send_email(current_user.email, subject, template)
        
        flash('Booking confirmed! Check your email for details.', 'success')
        return redirect(url_for('my_bookings'))
    
    return render_template('book.html', experiment=experiment, available_devices=experiment_devices)

@app.route('/my_bookings')
@login_required
def my_bookings():
    bookings = Booking.query.filter_by(user_id=current_user.id).order_by(Booking.start_time.desc()).all()
    
    # Update booking statuses
    now = datetime.now()
    for booking in bookings:
        if booking.status == 'UPCOMING':
            if now < booking.start_time:
                booking.status = 'UPCOMING'
            elif booking.start_time <= now <= booking.end_time:
                booking.status = 'ACTIVE'
            elif now > booking.end_time:
                booking.status = 'EXPIRED'
        elif booking.status == 'ACTIVE':
            if now > booking.end_time:
                booking.status = 'EXPIRED'
            elif booking.status == 'IN_PROGRESS':
                # Calculate duration from start and end time
                duration = (booking.end_time - booking.start_time).total_seconds() // 60
                if booking.started_at and now > booking.started_at + timedelta(minutes=duration):
                    booking.status = 'COMPLETED'
                    booking.completed_at = datetime.now()
    
    db.session.commit()
    return render_template('my_bookings.html', bookings=bookings)

@app.route('/cancel_booking/<int:booking_id>')
@login_required
def cancel_booking(booking_id):
    booking = Booking.query.get(booking_id)
    if not booking or booking.user_id != current_user.id:
        flash('Booking not found', 'danger')
        return redirect(url_for('my_bookings'))
    
    if booking.status != 'UPCOMING' and booking.status != 'ACTIVE':
        flash('Only upcoming or active bookings can be cancelled', 'danger')
        return redirect(url_for('my_bookings'))
    
    booking.status = 'CANCELLED'
    db.session.commit()
    flash('Booking cancelled successfully', 'success')
    return redirect(url_for('my_bookings'))

@app.route('/start_booking/<int:booking_id>')
@login_required
def start_booking(booking_id):
    booking = Booking.query.get(booking_id)
    if not booking or booking.user_id != current_user.id:
        flash('Booking not found', 'danger')
        return redirect(url_for('my_bookings'))
    
    now = datetime.now()
    if not (booking.start_time <= now <= booking.end_time):
        flash('Booking window has passed', 'danger')
        return redirect(url_for('my_bookings'))
    
    # Check if user already has an active session
    active_session = Session.query.filter_by(
        user_id=current_user.id,
        status='ACTIVE'
    ).first()
    
    if active_session:
        flash('You already have an active session. Please end your current session before starting a new one.', 'danger')
        return redirect(url_for('my_bookings'))
    
    # Create new session
    session = Session(
        booking_id=booking.id,
        user_id=current_user.id,
        session_key=booking.session_key,
        duration=(booking.end_time - booking.start_time).total_seconds() // 60,
        end_time=booking.end_time,
        ip_address=request.remote_addr
    )
    db.session.add(session)
    
    booking.status = 'IN_PROGRESS'
    booking.started_at = now
    db.session.commit()
    
    # Add to active sessions
    active_sessions[booking.session_key] = {
        'start_time': time.time(),
        'duration': session.duration,
        'expires_at': session.end_time.timestamp()
    }
    
    return redirect(url_for('experiment', key=booking.session_key))

# ---------- FLASH AND FIRMWARE ----------
@app.route('/flash', methods=['POST'])
@login_required
def flash_firmware():
    board = request.form.get('board', 'generic')
    port = request.form.get('port', '') or ''
    available_ports = list_serial_ports()
    default_port = available_ports[0] if available_ports else '/dev/ttyUSB0'
    port = port or default_port
    fw = request.files.get('firmware')
    if not fw:
        return jsonify({'status': 'No firmware uploaded'}), 400
    fname = secure_filename(fw.filename)
    dest = os.path.join(UPLOAD_DIR, fname)
    fw.save(dest)

    commands = {
        'esp32': f"esptool.py --chip esp32 --port {port} write_flash 0x10000 {dest}",
        'esp8266': f"esptool.py --port {port} write_flash 0x00000 {dest}",
        'arduino': f"avrdude -v -p atmega328p -c arduino -P {port} -b115200 -D -U flash:w:{dest}:i",
        'attiny': f"avrdude -v -p attiny85 -c usbasp -P {port} -U flash:w:{dest}:i",
        'stm32': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {dest} 0x08000000 verify reset exit\"",
        'nucleo_f446re': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {dest} 0x08000000 verify reset exit\"",
        'black_pill': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {dest} 0x08000000 verify reset exit\"",
        'msp430': f"mspdebug rf2500 'prog {dest}'",
        'tiva': f"openocd -f board/ti_ek-tm4c123gxl.cfg -c \"program {dest} verify reset exit\"",
        'tms320f28377s': f"python3 dsp/flash_tool.py {dest}",
        'generic': f"echo 'No flashing command configured for {board}. Uploaded to {dest}'"
    }

    cmd = commands.get(board, commands['generic'])
    socketio.start_background_task(run_flash_command, cmd, fname)
    return jsonify({'status': f'Flashing started for {board}', 'command': cmd})

def run_flash_command(cmd, filename=None):
    try:
        socketio.emit('flashing_status', f"Starting: {cmd}")
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in iter(p.stdout.readline, ''):
            if line is None:
                continue
            socketio.emit('flashing_status', line.strip())
        p.wait()
        rc = p.returncode
        msg = '✅ Flashing completed successfully' if rc == 0 else f'⚠️ Flashing ended with return code {rc}'
        socketio.emit('flashing_status', f'{msg} (file: {filename})')
    except Exception as e:
        socketio.emit('flashing_status', f'Error while flashing: {e}')

@app.route('/factory_reset', methods=['POST'])
@login_required
def factory_reset():
    try:
        data = request.get_json(force=True)
    except:
        data = request.form.to_dict()
    board = (data.get('board') or 'generic').lower()

    default_map = {
        'esp32': 'esp32_default.bin',
        'esp8266': 'esp32_default.bin',
        'arduino': 'arduino_default.hex',
        'attiny': 'attiny_default.hex',
        'stm32': 'stm32_default.bin',
        'nucleo_f446re': 'stm32_default.bin',
        'black_pill': 'stm32_default.bin',
        'msp430': 'generic_default.bin',
        'tiva': 'tiva_default.out',
        'tms320f28377s': 'tms320f28377s_default.out',
        'generic': 'generic_default.bin'
    }

    fname = default_map.get(board, default_map['generic'])
    fpath = os.path.join(DEFAULT_FW_DIR, fname)
    if not os.path.isfile(fpath):
        return jsonify({'error': f'Default firmware not found for board {board}: expected {fpath}'}), 404

    port = request.args.get('port') or ''
    available_ports = list_serial_ports()
    default_port = available_ports[0] if available_ports else '/dev/ttyUSB0'
    port = port or default_port
    commands = {
        'esp32': f"esptool.py --chip esp32 --port {port} write_flash 0x10000 {fpath}",
        'esp8266': f"esptool.py --port {port} write_flash 0x00000 {fpath}",
        'arduino': f"avrdude -v -p atmega328p -c arduino -P {port} -b115200 -D -U flash:w:{fpath}:i",
        'attiny': f"avrdude -v -p attiny85 -c usbasp -P {port} -U flash:w:{fpath}:i",
        'stm32': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {fpath} 0x08000000 verify reset exit\"",
        'nucleo_f446re': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {fpath} 0x08000000 verify reset exit\"",
        'black_pill': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {fpath} 0x08000000 verify reset exit\"",
        'msp430': f"mspdebug rf2500 'prog {fpath}'",
        'tiva': f"openocd -f board/ti_ek-tm4c123gxl.cfg -c \"program {fpath} verify reset exit\"",
        'tms320f28377s': f"python3 dsp/flash_tool.py {fpath}",
        'generic': f"echo 'No flashing command configured for {board}. Default firmware at {fpath}'"
    }
    cmd = commands.get(board, commands['generic'])
    socketio.start_background_task(run_flash_command, cmd, fname)
    return jsonify({'status': f'Factory reset started for {board}', 'command': cmd})

@app.route('/sop/<path:filename>')
@login_required
def serve_sop(filename):
    safe_path = os.path.join(SOP_DIR, filename)
    if not os.path.isfile(safe_path):
        abort(404)
    return send_from_directory(SOP_DIR, filename, as_attachment=True)

# ---------- MOCK GENERATOR ----------
def mock_data_generator():
    print("Mock data generator STARTED.")
    try:
        while True:
            sensor1 = 25.0 + random.uniform(-5.0, 5.0)
            sensor2 = 60.0 + random.uniform(-10.0, 10.0)
            sensor3 = 0.5 + random.uniform(-0.2, 0.2)
            sensor4 = 3.3 + random.uniform(-0.5, 0.5)
            payload = {
                'sensor1': round(sensor1, 2),
                'sensor2': round(sensor2, 2),
                'sensor3': round(sensor3, 3),
                'sensor4': round(sensor4, 2)
            }
            socketio.emit('sensor_data', payload)
            eventlet.sleep(0.1)
    except eventlet.greenlet.GreenletExit:
        print("Mock data generator KILLED.")
    except Exception as e:
        print("Mock data generator error:", e)

# ---------- SERIAL READER ----------
def serial_reader_worker(serial_obj):
    try:
        while not ser_stop.is_set():
            line = serial_obj.readline()
            if not line:
                continue
            try:
                text = line.decode(errors='replace').strip()
            except:
                text = str(line)
            socketio.emit('feedback', text)

            if any(sep in text for sep in [':', '=', '@', '>', '#', '^', '!', '$', '*', '%', '~', '\\', '|', '+', '-', ';', ',']) and any(c.isdigit() for c in text):
                trimmed = re.sub(r'^\d{1,2}:\d{2}:\d{2}\s*', '', text.strip())
                pairGroups = re.split(r'[,;]', trimmed)
                data = {}
                for group in pairGroups:
                    if not group.strip():
                        continue
                    normalized = re.sub(r'[:=>@#>^!$*~\\|+%\s&]+', ' ', group).strip()
                    tokens = re.split(r'\s+', normalized)
                    for i in range(0, len(tokens), 2):
                        if i + 1 < len(tokens):
                            k = tokens[i].strip().lower()
                            rawv = tokens[i + 1].strip()
                            try:
                                num = float(re.sub(r'[^\d\.\-+eE]', '', rawv))
                                if not math.isnan(num):
                                    data[k] = num
                            except:
                                pass
                if data:
                    socketio.start_background_task(send_sensor_data_to_clients, data)
    except Exception as e:
        socketio.emit('feedback', f'[serial worker stopped] {e}')

# ---------- SOCKET HANDLERS ----------
@socketio.on('connect')
def on_connect():
    print("[DEBUG] Client connected:", request.sid)
    emit('ports_list', list_serial_ports())
    emit('feedback', 'Server: socket connected')

@socketio.on('list_ports')
def handle_list_ports():
    emit('ports_list', list_serial_ports())

@socketio.on('connect_serial')
def handle_connect_serial(data):
    global ser, ser_stop, data_generator_thread
    port = data.get('port')
    baud = int(data.get('baud', 115200))
    if not port:
        emit('serial_status', {'status': 'error', 'message': 'No port selected'})
        return
    if serial is None:
        emit('serial_status', {'status': 'error', 'message': 'pyserial not available on server'})
        return
    with serial_lock:
        try:
            if ser and ser.is_open:
                ser.close()
            if data_generator_thread:
                data_generator_thread.kill()
                data_generator_thread = None

            ser = serial.Serial(port, baud, timeout=1)
            ser_stop.clear()
            eventlet.spawn(serial_reader_worker, ser)
            emit('serial_status', {'status': 'connected', 'port': port, 'baud': baud})
        except Exception as e:
            emit('serial_status', {'status': 'error', 'message': str(e)})

@socketio.on('disconnect_serial')
def handle_disconnect_serial():
    global ser, ser_stop, data_generator_thread
    with serial_lock:
        try:
            ser_stop.set()
            if ser and ser.is_open:
                ser.close()
            if data_generator_thread is None:
                data_generator_thread = eventlet.spawn(mock_data_generator)
            emit('serial_status', {'status': 'disconnected'})
        except Exception as e:
            emit('serial_status', {'status': 'error', 'message': str(e)})

@socketio.on('send_command')
def handle_send_command(data):
    global ser
    cmd = data.get('cmd', '')
    out = cmd + ("\n" if not cmd.endswith("\n") else "")
    try:
        with serial_lock:
            if ser and ser.is_open:
                ser.write(out.encode())
                emit('feedback', f'SENT> {cmd}')
            else:
                emit('feedback', f'[no-serial] {cmd}')
    except Exception as e:
        emit('feedback', f'[send error] {e}')

@socketio.on('waveform_config')
def handle_waveform_config(cfg):
    shape = cfg.get('shape'); freq = cfg.get('freq'); amp = cfg.get('amp')
    msg = f'WAVE {shape} FREQ {freq} AMP {amp}'
    emit('feedback', f'[waveform] {msg}')
    with serial_lock:
        try:
            if ser and ser.is_open:
                ser.write((msg + "\n").encode())
        except Exception as e:
            emit('feedback', f'[waveform send error] {e}')

def send_sensor_data_to_clients(data):
    try:
        with app.app_context():
            socketio.emit('sensor_data', data, namespace='/')
            print("[DEBUG] Emitted to clients:", data)
    except Exception as e:
        print("[ERROR] Failed to emit sensor_data:", e)

# ---------- LAB PI API ENDPOINTS ----------
@app.route('/api/lab/register', methods=['POST'])
def register_lab_pi():
    """Register a Lab Pi with Admin Pi"""
    try:
        data = request.get_json()
        
        # Validate API key
        api_key = request.headers.get('X-API-Key')
        if api_key != config.get('security.api_key'):
            return jsonify({'success': False, 'message': 'Invalid API key'}), 401
        
        mac_address = data.get('mac_address')
        if not mac_address:
            return jsonify({'success': False, 'message': 'MAC address required'}), 400
        
        # Check if device already registered
        device = Device.query.filter_by(mac_address=mac_address).first()
        if device:
            # Update existing device
            device.ip_address = data.get('ip_address', device.ip_address)
            device.device_name = data.get('device_name', device.device_name)
            device.device_type = data.get('device_type', device.device_type)
            device.location = data.get('location', device.location)
            device.experiment_capabilities = json.dumps(data.get('experiment_capabilities', []))
            device.firmware_version = data.get('firmware_version', device.firmware_version)
            device.hardware_version = data.get('hardware_version', device.hardware_version)
            device.status = 'ONLINE'
            device.last_seen = datetime.utcnow()
            device.last_heartbeat = datetime.utcnow()
        else:
            # Create new device
            device = Device(
                mac_address=mac_address,
                ip_address=data.get('ip_address'),
                device_name=data.get('device_name', 'Unknown Lab Pi'),
                device_type=data.get('device_type', 'raspberry-pi'),
                location=data.get('location', 'Unknown'),
                experiment_capabilities=json.dumps(data.get('experiment_capabilities', [])),
                firmware_version=data.get('firmware_version', '1.0.0'),
                hardware_version=data.get('hardware_version', 'RPi4'),
                status='ONLINE',
                last_seen=datetime.utcnow(),
                last_heartbeat=datetime.utcnow()
            )
            db.session.add(device)
        
        db.session.commit()
        
        log_entry = SystemLog(
            level='INFO',
            category='SYSTEM',
            message=f"Lab Pi registered/updated: {device.device_name} ({device.ip_address})",
            device_id=device.id
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'device_id': device.id,
            'message': 'Lab Pi registered successfully'
        })
    except Exception as e:
        print(f"Error registering Lab Pi: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/lab/heartbeat', methods=['POST'])
def lab_heartbeat():
    """Handle Lab Pi heartbeat"""
    try:
        data = request.get_json()
        
        # Validate API key
        api_key = request.headers.get('X-API-Key')
        if api_key != config.get('security.api_key'):
            return jsonify({'success': False, 'message': 'Invalid API key'}), 401
        
        mac_address = data.get('mac_address')
        if not mac_address:
            return jsonify({'success': False, 'message': 'MAC address required'}), 400
        
        # Find device
        device = Device.query.filter_by(mac_address=mac_address).first()
        if not device:
            # Auto-register device if not found
            return register_lab_pi()
        
        # Update device information
        device.ip_address = data.get('ip_address', device.ip_address)
        device.status = data.get('status', 'ONLINE')
        device.last_seen = datetime.utcnow()
        device.last_heartbeat = datetime.utcnow()
        
        # Update system metrics if provided
        if 'cpu_usage' in data:
            device.cpu_usage = data.get('cpu_usage')
        if 'ram_usage' in data:
            device.ram_usage = data.get('ram_usage')
        if 'temperature' in data:
            device.temperature = data.get('temperature')
        
        # Create metric entry
        metric = DeviceMetric(
            device_id=device.id,
            cpu_usage=device.cpu_usage,
            ram_usage=device.ram_usage,
            temperature=device.temperature
        )
        db.session.add(metric)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Heartbeat received'})
    except Exception as e:
        print(f"Error handling heartbeat: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/telemetry', methods=['POST'])
def receive_telemetry():
    """Receive telemetry data from Lab Pi"""
    try:
        data = request.get_json()
        
        # Validate API key
        api_key = request.headers.get('X-API-Key')
        if api_key != config.get('security.api_key'):
            return jsonify({'success': False, 'message': 'Invalid API key'}), 401
        
        mac_address = data.get('mac_address')
        if not mac_address:
            return jsonify({'success': False, 'message': 'MAC address required'}), 400
        
        # Find device
        device = Device.query.filter_by(mac_address=mac_address).first()
        if not device:
            return jsonify({'success': False, 'message': 'Device not found'}), 404
        
        # TODO: Handle telemetry data (store in database, forward to WebSocket, etc.)
        sensor_data = data.get('sensor_data', {})
        timestamp = data.get('timestamp', datetime.utcnow().isoformat())
        
        # Forward telemetry to connected clients
        socketio.emit('sensor_data', {
            'device_id': device.id,
            'device_name': device.device_name,
            'timestamp': timestamp,
            'data': sensor_data
        })
        
        return jsonify({'success': True, 'message': 'Telemetry received'})
    except Exception as e:
        print(f"Error receiving telemetry: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/lab/send_command', methods=['POST'])
def send_command_to_lab():
    """Send a command to a specific Lab Pi"""
    try:
        data = request.get_json()
        
        # Validate API key
        api_key = request.headers.get('X-API-Key')
        if api_key != config.get('security.api_key'):
            return jsonify({'success': False, 'message': 'Invalid API key'}), 401
        
        device_id = data.get('device_id')
        command = data.get('command')
        
        if not device_id or not command:
            return jsonify({'success': False, 'message': 'Device ID and command required'}), 400
        
        # Find device
        device = Device.query.get(device_id)
        if not device:
            return jsonify({'success': False, 'message': 'Device not found'}), 404
        
        # Send command to Lab Pi
        lab_url = f"http://{device.ip_address}:5001/api/experiment/{command}"
        response = requests.post(lab_url, json=data.get('params', {}), headers={'X-API-Key': config.get('security.api_key')})
        
        if response.status_code == 200:
            return jsonify({'success': True, 'message': 'Command sent successfully', 'data': response.json()})
        else:
            return jsonify({'success': False, 'message': f'Failed to send command: {response.text}'}), response.status_code
    except Exception as e:
        print(f"Error sending command: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/lab/get_available', methods=['GET'])
def get_available_labs():
    """Get all available Lab Pis for a specific experiment"""
    try:
        experiment_id = request.args.get('experiment_id', type=int)
        
        # Get all online and available devices
        devices = Device.query.filter_by(status='ONLINE', maintenance_mode=False, current_booking_id=None).all()
        
        if experiment_id:
            # Filter devices that support the specified experiment
            available_devices = []
            for device in devices:
                if device.get_experiment_capabilities() and experiment_id in device.get_experiment_capabilities():
                    available_devices.append(device)
        else:
            available_devices = devices
        
        return jsonify({
            'success': True,
            'devices': [{
                'id': device.id,
                'name': device.device_name,
                'type': device.device_type,
                'ip_address': device.ip_address,
                'location': device.location,
                'capabilities': device.get_experiment_capabilities()
            } for device in available_devices]
        })
    except Exception as e:
        print(f"Error getting available labs: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/lab/assign', methods=['POST'])
def assign_lab_to_booking():
    """Assign a Lab Pi to a booking"""
    try:
        data = request.get_json()
        
        # Validate API key
        api_key = request.headers.get('X-API-Key')
        if api_key != config.get('security.api_key'):
            return jsonify({'success': False, 'message': 'Invalid API key'}), 401
        
        booking_id = data.get('booking_id')
        device_id = data.get('device_id')
        
        if not booking_id or not device_id:
            return jsonify({'success': False, 'message': 'Booking ID and Device ID required'}), 400
        
        # Find booking and device
        booking = Booking.query.get(booking_id)
        device = Device.query.get(device_id)
        
        if not booking or not device:
            return jsonify({'success': False, 'message': 'Booking or device not found'}), 404
        
        # Check if device is available
        if device.current_booking_id is not None or device.status != 'ONLINE' or device.maintenance_mode:
            return jsonify({'success': False, 'message': 'Device is not available'}), 400
        
        # Assign device to booking
        device.current_booking_id = booking_id
        device.status = 'BUSY'
        db.session.commit()
        
        log_entry = SystemLog(
            level='INFO',
            category='EXPERIMENT',
            message=f"Lab Pi '{device.device_name}' assigned to booking #{booking_id}",
            device_id=device.id
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Lab Pi assigned successfully'})
    except Exception as e:
        print(f"Error assigning Lab Pi: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/lab/release', methods=['POST'])
def release_lab_pi():
    """Release a Lab Pi from a booking"""
    try:
        data = request.get_json()
        
        # Validate API key
        api_key = request.headers.get('X-API-Key')
        if api_key != config.get('security.api_key'):
            return jsonify({'success': False, 'message': 'Invalid API key'}), 401
        
        booking_id = data.get('booking_id')
        
        if not booking_id:
            return jsonify({'success': False, 'message': 'Booking ID required'}), 400
        
        # Find device with this booking
        device = Device.query.filter_by(current_booking_id=booking_id).first()
        
        if not device:
            return jsonify({'success': False, 'message': 'Device not found for this booking'}), 404
        
        # Release the device
        device.current_booking_id = None
        device.status = 'ONLINE'
        db.session.commit()
        
        log_entry = SystemLog(
            level='INFO',
            category='EXPERIMENT',
            message=f"Lab Pi '{device.device_name}' released from booking #{booking_id}",
            device_id=device.id
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Lab Pi released successfully'})
    except Exception as e:
        print(f"Error releasing Lab Pi: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ---------- DEVICE MONITORING ----------
def check_device_heartbeats():
    """Check if any devices have expired heartbeats"""
    while True:
        try:
            with app.app_context():
                devices = Device.query.all()
                for device in devices:
                    if device.is_heartbeat_expired() and device.status != 'OFFLINE':
                        device.status = 'OFFLINE'
                        db.session.commit()
                        log_entry = SystemLog(
                            level='WARNING',
                            category='SYSTEM',
                            message=f"Lab Pi '{device.device_name}' is offline (heartbeat expired)",
                            device_id=device.id
                        )
                        db.session.add(log_entry)
                        db.session.commit()
        
            # Check every 30 seconds
            time.sleep(30)
        except Exception as e:
            print(f"Error checking device heartbeats: {e}")
            time.sleep(30)

# Start device monitoring thread
def start_device_monitoring():
    if not hasattr(app, 'device_monitor_thread'):
        app.device_monitor_thread = threading.Thread(target=check_device_heartbeats, daemon=True)
        app.device_monitor_thread.start()
        print("✅ Device heartbeat monitoring started")

# Run device monitoring when the application starts
with app.app_context():
    start_device_monitoring()

# ---------- MAIN ----------
if __name__ == '__main__':
    import socket
    def check_port(port, name):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        if result == 0:
            print(f"✓ {name} is running on port {port}")
            return True
        else:
            print(f"✗ {name} is NOT running on port {port}")
            return False

    print("========================================")
    print("Virtual Lab Server Starting...")
    print("========================================")

    # Check if we're in admin mode
    if config.is_admin_pi():
        print("✅ Admin Pi mode enabled")
    else:
        print("⚠️  Not running in Admin Pi mode")

    audio_running = check_port(9000, "Audio server")
    if not audio_running:
        print("\n⚠️  Audio service not detected!")
        print("   To enable audio, run:")
        print("   sudo systemctl enable audio_stream.service")
        print("   sudo systemctl start audio_stream.service")

    print("\nStarting Flask server on port 5000...")
    print("========================================")

    try:
        socketio.run(app, host='0.0.0.0', port=5000)
    finally:
        print("Main server stopped")
