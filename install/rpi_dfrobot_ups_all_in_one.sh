#!/bin/bash
# DFRobot UPS - Raspberry Pi 5
# Fully automated for remote lab usage

set -e

echo "========================================"
echo "🔋 DFRobot UPS All-in-One Setup"
echo "========================================"

### 1️⃣ EEPROM CONFIG ###
echo "⚙️ Configuring EEPROM..."

TMP=$(mktemp)
sudo rpi-eeprom-config > "$TMP"

sed -i 's/^POWER_OFF_ON_HALT=.*/POWER_OFF_ON_HALT=1/' "$TMP" || true
grep -q POWER_OFF_ON_HALT "$TMP" || echo "POWER_OFF_ON_HALT=1" >> "$TMP"

grep -q PSU_MAX_CURRENT "$TMP" || echo "PSU_MAX_CURRENT=5000" >> "$TMP"

sudo rpi-eeprom-config --apply "$TMP"
rm -f "$TMP"

echo "✅ EEPROM done"

### 2️⃣ ENABLE I2C ###
echo "🔌 Enabling I2C..."

sudo raspi-config nonint do_i2c 0

for m in i2c-dev i2c-bcm2835; do
    lsmod | grep -q $m || sudo modprobe $m
done

echo "✅ I2C enabled"

### 3️⃣ DEPENDENCIES ###
echo "📦 Installing dependencies..."

sudo apt update
sudo apt install -y \
    i2c-tools \
    python3-smbus \
    python3-pip

pip3 install --break-system-packages smbus2

echo "✅ Packages installed"

### 4️⃣ I2C SCAN ###
echo "🔍 Scanning I2C bus..."
i2cdetect -y 1 || true

### 5️⃣ UPS MONITOR (AUTO-DETECT) ###
echo "🧠 Installing UPS monitor..."

UPS_PY="/usr/local/bin/dfrobot_ups.py"

sudo tee "$UPS_PY" > /dev/null << 'EOF'
#!/usr/bin/env python3
import time
from smbus2 import SMBus

BUS = 1
ADDR_MAX17048 = 0x36
ADDR_INA219   = 0x40

def swap16(x):
    return ((x & 0xFF) << 8) | (x >> 8)

bus = SMBus(BUS)

def max17048_soc():
    try:
        raw = bus.read_word_data(ADDR_MAX17048, 0x04)
        return swap16(raw) / 256.0
    except:
        return None

def ina219_voltage():
    try:
        raw = bus.read_word_data(ADDR_INA219, 0x02)
        return swap16(raw) * 0.00125
    except:
        return None

def ina219_current():
    try:
        raw = bus.read_word_data(ADDR_INA219, 0x04)
        val = swap16(raw)
        if val > 32767:
            val -= 65536
        return val * 0.001
    except:
        return None

def ac_status(current):
    if current is None:
        return "UNKNOWN"
    return "AC_CONNECTED" if current > 0 else "ON_BATTERY"

print("DFRobot UPS Monitor started")

while True:
    soc = max17048_soc()
    voltage = ina219_voltage()
    current = ina219_current()
    ac = ac_status(current)

    print(
        f"🔋 SOC: {soc if soc is not None else 'N/A'}% | "
        f"⚡ Voltage: {voltage if voltage else 'N/A'} V | "
        f"🔌 Current: {current if current else 'N/A'} A | "
        f"🔄 Power: {ac}"
    )

    time.sleep(5)
EOF

sudo chmod +x "$UPS_PY"

echo "✅ UPS monitor installed"

### 6️⃣ SYSTEMD SERVICE ###
echo "⚙️ Creating service..."

sudo tee /etc/systemd/system/dfrobot-ups.service > /dev/null << EOF
[Unit]
Description=DFRobot UPS Monitor
After=multi-user.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/dfrobot_ups.py
Restart=always
RestartSec=3
User=$REAL_USER

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable dfrobot-ups.service

echo "========================================"
echo "🎉 DFRobot UPS READY"
echo "🔁 Reboot required"
echo "========================================"
