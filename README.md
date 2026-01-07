# Virtual Lab - Remote Embedded Systems Laboratory

A Flask-based web application for remote access to embedded systems laboratories with support for multiple microcontroller boards, WebRTC audio streaming, and real-time sensor data visualization.

## Features

- **Multi-board Support**: ESP32, ESP8266, Arduino, ATtiny, STM32, MSP430, TIVA, and more
- **Firmware Flashing**: Flash firmware via web interface using esptool, avrdude, openocd, mspdebug
- **Real-time Serial Communication**: Bidirectional communication with embedded devices
- **Sensor Data Visualization**: Real-time charts with WebSocket support
- **WebRTC Audio Streaming**: Live audio from laboratory environment
- **Session Management**: Time-limited access sessions with secure keys

## Installation on Fresh Raspberry Pi

### Option 1: Automated Installation (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/virtual_lab.git
cd virtual_lab
```

2. Run the installation script:
```bash
chmod +x install.sh
./install.sh
```

3. Reboot for serial port permissions:
```bash
sudo reboot
```

4. Start the service:
```bash
sudo systemctl start virtual_lab
```

### Option 2: Manual Installation

```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3-pip python3-venv python3-dev git avrdude openocd esptool libportaudio2 arecord aplay ffmpeg

# Clone and setup
git clone https://github.com/YOUR_USERNAME/virtual_lab.git
cd virtual_lab

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create directories
mkdir -p uploads default_fw static/sop

# Setup systemd service
sudo cp virtual_lab.service /etc/systemd/system/
sudo chmod 644 /etc/systemd/system/virtual_lab.service
sudo systemctl daemon-reload
sudo systemctl enable virtual_lab.service
sudo systemctl start virtual_lab

# Add user to dialout group (for serial port access)
sudo usermod -a -G dialout $USER
```

## Project Structure

```
virtual_lab/
├── app.py                 # Main Flask application
├── install.sh             # Installation script for fresh Pi
├── setup-git.sh          # GitHub repository setup script
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── templates/            # HTML templates
│   ├── homepage.html
│   ├── index.html
│   ├── chart.html
│   └── camera.html
├── static/               # Static files
│   └── sop/             # Standard Operating Procedures PDFs
├── Audio/               # WebRTC audio streaming
│   ├── server.py
│   └── client.html
├── my_webrtc/           # Additional WebRTC modules
│   ├── appp.py
│   └── camera.py
├── default_fw/          # Default firmware files
│   ├── esp32_default.bin
│   ├── arduino_default.hex
│   └── ...
├── uploads/             # User uploaded firmware
├── lm4tools/           # LM4F flash tools
└── firmware_assets/    # Additional firmware assets
```

## Usage

1. Access the web interface at `http://YOUR_PI_IP:5000`
2. Create a session for time-limited access
3. Connect to serial port for your microcontroller
4. Flash firmware or send commands
5. View real-time sensor data on charts

## Supported Boards

| Board | Flash Command |
|-------|--------------|
| ESP32 | esptool.py --chip esp32 --port <port> write_flash 0x10000 <firmware> |
| ESP8266 | esptool.py --port <port> write_flash 0x00000 <firmware> |
| Arduino | avrdude -v -p atmega328p -c arduino -P <port> -b115200 -D -U flash:w:<firmware>:i |
| ATtiny | avrdude -v -p attiny85 -c usbasp -P <port> -U flash:w:<firmware>:i |
| STM32 | openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c "program <firmware> 0x08000000 verify reset exit" |
| TIVA | openocd -f board/ti_ek-tm4c123gxl.cfg -c "program <firmware> verify reset exit" |

## API Endpoints

- `POST /flash` - Flash firmware to board
- `POST /factory_reset` - Restore default firmware
- `GET /ports` - List available serial ports
- `GET /chart` - Sensor data visualization
- `GET /camera` - Camera streaming interface

## License

MIT License
