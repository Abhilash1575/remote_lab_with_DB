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
from werkzeug.utils import secure_filename

# Import configuration
from config import config

# Import GPIO and Serial modules with fallback
try:
    import lgpio
    RELAY_PIN = config.get('hardware.relay_pin', 26)
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

# System monitoring
import psutil

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

socketio = SocketIO(app, async_mode='eventlet')
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# ---------- HARDWARE CONTROL ----------
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

def send_admin_request(endpoint, data=None, method='GET'):
    """Send a request to the Admin Pi"""
    import requests
    admin_url = config.get_admin_url()
    api_key = config.get('security.api_key')
    
    headers = {
        'Content-Type': 'application/json',
        'X-API-Key': api_key
    }
    
    try:
        url = f"{admin_url}/{endpoint}"
        if method == 'GET':
            response = requests.get(url, headers=headers, params=data)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data)
        elif method == 'PUT':
            response = requests.put(url, headers=headers, json=data)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers, params=data)
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Admin request failed: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error sending request to admin: {e}")
        return None

# ---------- HEARTBEAT MONITORING ----------
def send_heartbeat():
    """Send heartbeat to Admin Pi"""
    data = {
        "mac_address": config.get('lab.mac_address'),
        "ip_address": config.get('lab.ip_address'),
        "device_name": config.get('lab.device_name'),
        "device_type": config.get('lab.device_type'),
        "location": config.get('lab.location'),
        "experiment_capabilities": config.get_experiment_capabilities(),
        "firmware_version": "1.0.0",
        "hardware_version": "RPi4",
        "cpu_usage": psutil.cpu_percent(),
        "ram_usage": psutil.virtual_memory().percent,
        "temperature": get_cpu_temperature(),
        "status": "ONLINE"
    }
    
    response = send_admin_request('api/lab/heartbeat', data, 'POST')
    if response:
        print("Heartbeat sent successfully")
    else:
        print("Failed to send heartbeat")

def get_cpu_temperature():
    """Get CPU temperature (Raspberry Pi specific)"""
    try:
        temp = os.popen("vcgencmd measure_temp").readline()
        return float(temp.replace("temp=", "").replace("'C\n", ""))
    except Exception as e:
        print(f"Error getting CPU temperature: {e}")
        return None

def heartbeat_loop():
    """Continuous heartbeat loop"""
    interval = config.get('lab.heartbeat_interval', 10)
    while True:
        send_heartbeat()
        time.sleep(interval)

# Start heartbeat thread
def start_heartbeat():
    if not hasattr(app, 'heartbeat_thread'):
        app.heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
        app.heartbeat_thread.start()
        print("✅ Heartbeat monitoring started")

# ---------- REGISTRATION ----------
def register_with_admin():
    """Register this Lab Pi with Admin Pi"""
    data = {
        "mac_address": config.get('lab.mac_address'),
        "ip_address": config.get('lab.ip_address'),
        "device_name": config.get('lab.device_name'),
        "device_type": config.get('lab.device_type'),
        "location": config.get('lab.location'),
        "experiment_capabilities": config.get_experiment_capabilities(),
        "firmware_version": "1.0.0",
        "hardware_version": "RPi4"
    }
    
    response = send_admin_request('api/lab/register', data, 'POST')
    if response and response.get('success'):
        print(f"✅ Lab Pi registered successfully (ID: {response.get('device_id')})")
        return response.get('device_id')
    else:
        print("❌ Failed to register with Admin Pi")
        return None

# ---------- EXPERIMENT CONTROL ----------
@app.route('/api/experiment/flash', methods=['POST'])
def flash_firmware():
    """Flash firmware to microcontroller"""
    try:
        data = request.get_json()
        board = data.get('board', 'generic')
        firmware_data = data.get('firmware_data')
        port = data.get('port', '/dev/ttyUSB0')
        
        # Save firmware to file
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.hex', delete=False) as f:
            f.write(bytes.fromhex(firmware_data))
            firmware_path = f.name
        
        commands = {
            'esp32': f"esptool.py --chip esp32 --port {port} write_flash 0x10000 {firmware_path}",
            'esp8266': f"esptool.py --port {port} write_flash 0x00000 {firmware_path}",
            'arduino': f"avrdude -v -p atmega328p -c arduino -P {port} -b115200 -D -U flash:w:{firmware_path}:i",
            'attiny': f"avrdude -v -p attiny85 -c usbasp -P {port} -U flash:w:{firmware_path}:i",
            'stm32': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {firmware_path} 0x08000000 verify reset exit\"",
            'nucleo_f446re': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {firmware_path} 0x08000000 verify reset exit\"",
            'black_pill': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {firmware_path} 0x08000000 verify reset exit\"",
            'msp430': f"mspdebug rf2500 'prog {firmware_path}'",
            'tiva': f"openocd -f board/ti_ek-tm4c123gxl.cfg -c \"program {firmware_path} verify reset exit\"",
            'tms320f28377s': f"python3 dsp/flash_tool.py {firmware_path}",
            'generic': f"echo 'No flashing command configured for {board}. Uploaded to {firmware_path}'"
        }
        
        cmd = commands.get(board, commands['generic'])
        socketio.start_background_task(run_flash_command, cmd, firmware_path)
        
        return jsonify({'success': True, 'message': f'Flashing started for {board}'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

def run_flash_command(cmd, filename):
    """Run flash command and emit status updates"""
    try:
        socketio.emit('flashing_status', f"Starting: {cmd}")
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in iter(p.stdout.readline, ''):
            if line:
                socketio.emit('flashing_status', line.strip())
        p.wait()
        rc = p.returncode
        msg = '✅ Flashing completed successfully' if rc == 0 else f'⚠️ Flashing ended with return code {rc}'
        socketio.emit('flashing_status', f'{msg} (file: {filename})')
        
        # Clean up temporary file
        try:
            os.remove(filename)
        except:
            pass
    except Exception as e:
        socketio.emit('flashing_status', f'Error while flashing: {e}')

@app.route('/api/experiment/relay', methods=['POST'])
def toggle_relay_api():
    """Toggle relay via API"""
    try:
        data = request.get_json()
        state = data.get('state')
        
        if state == 'on':
            success = relay_on()
        elif state == 'off':
            success = relay_off()
        else:
            return jsonify({'success': False, 'message': 'Invalid state'}), 400
        
        return jsonify({'success': success, 'status': state})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/experiment/start', methods=['POST'])
def start_experiment():
    """Start an experiment"""
    try:
        data = request.get_json()
        booking_id = data.get('booking_id')
        session_key = data.get('session_key')
        
        # TODO: Implement experiment starting logic
        
        return jsonify({'success': True, 'message': 'Experiment started'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/experiment/stop', methods=['POST'])
def stop_experiment():
    """Stop an experiment"""
    try:
        data = request.get_json()
        booking_id = data.get('booking_id')
        
        # Turn off relay
        relay_off()
        
        # TODO: Implement experiment stopping logic
        
        return jsonify({'success': True, 'message': 'Experiment stopped'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ---------- TELEMETRY ----------
@app.route('/api/telemetry/send', methods=['POST'])
def send_telemetry():
    """Send telemetry data to Admin Pi"""
    try:
        data = request.get_json()
        send_admin_request('api/telemetry', data, 'POST')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

def send_sensor_data(data):
    """Send sensor data to Admin Pi"""
    telemetry_data = {
        "mac_address": config.get('lab.mac_address'),
        "timestamp": datetime.utcnow().isoformat(),
        "sensor_data": data
    }
    send_admin_request('api/telemetry', telemetry_data, 'POST')

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
    # TODO: Implement serial connection
    emit('serial_status', {'status': 'connected', 'port': data.get('port'), 'baud': data.get('baud')})

@socketio.on('disconnect_serial')
def handle_disconnect_serial():
    # TODO: Implement serial disconnection
    emit('serial_status', {'status': 'disconnected'})

@socketio.on('send_command')
def handle_send_command(data):
    # TODO: Implement command sending
    cmd = data.get('cmd', '')
    emit('feedback', f'SENT> {cmd}')

# ---------- HEALTH CHECK ----------
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'device_info': {
            'name': config.get('lab.device_name'),
            'type': config.get('lab.device_type'),
            'mac_address': config.get('lab.mac_address'),
            'ip_address': config.get('lab.ip_address')
        },
        'system_info': {
            'cpu_usage': psutil.cpu_percent(),
            'ram_usage': psutil.virtual_memory().percent,
            'temperature': get_cpu_temperature()
        }
    })

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
    print("Lab Pi Server Starting...")
    print("========================================")
    
    # Register with Admin Pi
    print("\nRegistering with Admin Pi...")
    device_id = register_with_admin()
    if device_id:
        print(f"✅ Lab Pi registered with ID: {device_id}")
    else:
        print("❌ Failed to register. Check Admin Pi connection.")
    
    # Start heartbeat
    print("\nStarting heartbeat...")
    start_heartbeat()
    
    audio_running = check_port(9000, "Audio server")
    if not audio_running:
        print("\n⚠️  Audio service not detected!")
        print("   To enable audio, run:")
        print("   sudo systemctl enable audio_stream.service")
        print("   sudo systemctl start audio_stream.service")

    print("\nStarting Flask server on port 5001...")
    print("========================================")

    try:
        socketio.run(app, host='0.0.0.0', port=5001)
    finally:
        print("Lab Pi server stopped")