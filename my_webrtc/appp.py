from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import serial
import serial.tools.list_ports
import threading
import time

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# ====== SERIAL CONFIG ======
SERIAL_PORT = "/dev/ttyUSB0"
BAUD_RATE = 115200
ser = None
serial_thread = None
serial_running = True


# ====== OPEN SERIAL CONNECTION ======
def open_serial():
    global ser
    try:
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
        print(f"[INFO] Connected to {SERIAL_PORT} @ {BAUD_RATE}")
    except Exception as e:
        print(f"[ERROR] Could not open serial port: {e}")
        ser = None


# ====== READ SERIAL DATA ======
def read_serial():
    global ser, serial_running
    while serial_running:
        if ser and ser.in_waiting > 0:
            try:
                line = ser.readline().decode("utf-8", errors="ignore").strip()
                if line:
                    socketio.emit("serial_log", {"data": line})
            except Exception as e:
                print(f"[WARN] Serial read error: {e}")
        time.sleep(0.05)


# ====== ROUTES ======
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/send_command", methods=["POST"])
def send_command():
    global ser
    data = request.json
    cmd = data.get("command", "")
    if ser:
        ser.write((cmd + "\n").encode())
        return jsonify({"status": "ok", "sent": cmd})
    else:
        return jsonify({"status": "error", "msg": "Serial not connected"})


@app.route("/list_ports")
def list_ports():
    ports = [p.device for p in serial.tools.list_ports.comports()]
    return jsonify({"ports": ports})


# ====== SOCKET EVENTS ======
@socketio.on("connect")
def handle_connect():
    print("Client connected")
    emit("serial_log", {"data": "[System] Connected to Flask server"})


@socketio.on("disconnect")
def handle_disconnect():
    print("Client disconnected")


# ====== MAIN ======
if __name__ == "__main__":
    open_serial()
    serial_thread = threading.Thread(target=read_serial, daemon=True)
    serial_thread.start()
    socketio.run(app, host="0.0.0.0", port=5000)
