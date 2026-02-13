import lgpio
import sys

RELAY_PIN = 26

# Keep a persistent handle to GPIO chip
gpio_handle = None

def init_gpio():
    """Initialize GPIO chip handle"""
    global gpio_handle
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
    """Turn the relay ON (power supply to experiments)"""
    if not init_gpio():
        return False
    try:
        lgpio.gpio_write(gpio_handle, RELAY_PIN, 0)  # Most relay modules are ACTIVE LOW
        print("Relay ON")
        return True
    except Exception as e:
        print(f"Error turning relay ON: {e}")
        return False

def relay_off():
    """Turn the relay OFF (power supply to experiments off)"""
    if not init_gpio():
        return False
    try:
        lgpio.gpio_write(gpio_handle, RELAY_PIN, 1)  # Most relay modules are ACTIVE LOW
        print("Relay OFF")
        return True
    except Exception as e:
        print(f"Error turning relay OFF: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 relay_control.py on | off")
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "on":
        relay_on()
    elif cmd == "off":
        relay_off()
    else:
        print("Invalid command! Use on or off")
