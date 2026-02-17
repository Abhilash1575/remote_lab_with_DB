import json
import os
import socket
from typing import Dict, Any, Optional

class Config:
    """Configuration manager for the virtual lab system"""
    
    _instance = None
    _config = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_config()
        return cls._instance
    
    def _load_config(self):
        """Load configuration from config.json file"""
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
        
        if not os.path.exists(config_path):
            self._create_default_config(config_path)
        
        try:
            with open(config_path, 'r') as f:
                self._config = json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            self._create_default_config(config_path)
            with open(config_path, 'r') as f:
                self._config = json.load(f)
    
    def _create_default_config(self, config_path):
        """Create a default config.json file if it doesn't exist"""
        default_config = {
            "admin": {
                "server_ip": self._get_local_ip(),
                "server_port": 5000,
                "enable_ssl": False,
                "ssl_cert": "cert.pem",
                "ssl_key": "key.pem"
            },
            "lab": {
                "device_name": "Lab Pi",
                "device_type": "raspberry-pi",
                "mac_address": self._get_mac_address(),
                "ip_address": self._get_local_ip(),
                "location": "Unknown",
                "experiment_capabilities": [1, 2, 3],
                "heartbeat_interval": 10,
                "timeout": 30
            },
            "database": {
                "type": "sqlite",
                "path": "vlab.db",
                "host": "",
                "port": "",
                "name": "",
                "username": "",
                "password": ""
            },
            "mqtt": {
                "enabled": False,
                "broker": "localhost",
                "port": 1883,
                "username": "",
                "password": "",
                "topic_prefix": "vlab/"
            },
            "hardware": {
                "relay_pin": 26,
                "serial_ports": ["/dev/ttyUSB0", "/dev/ttyACM0"],
                "baud_rates": [9600, 115200],
                "camera_enabled": True,
                "camera_port": 8080,
                "audio_enabled": True,
                "audio_port": 9000
            },
            "security": {
                "api_key": self._generate_api_key(),
                "enable_authentication": True,
                "max_session_duration": 3600,
                "emergency_shutdown_pin": 17
            }
        }
        
        try:
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            print(f"Created default config at {config_path}")
        except Exception as e:
            print(f"Error creating config: {e}")
    
    def _get_local_ip(self) -> str:
        """Get the local IP address of the device"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            print(f"Error getting local IP: {e}")
            return '127.0.0.1'
    
    def _get_mac_address(self) -> str:
        """Get the MAC address of the device"""
        try:
            import uuid
            mac = uuid.getnode()
            return ':'.join(('%012x' % mac)[i:i+2] for i in range(0, 12, 2))
        except Exception as e:
            print(f"Error getting MAC address: {e}")
            return '00:00:00:00:00:00'
    
    def _generate_api_key(self) -> str:
        """Generate a random API key"""
        import secrets
        import string
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    
    def get(self, path: str, default: Any = None) -> Any:
        """Get a config value using dot notation (e.g., 'admin.server_ip')"""
        keys = path.split('.')
        value = self._config
        
        for key in keys:
            if key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, path: str, value: Any) -> None:
        """Set a config value using dot notation"""
        keys = path.split('.')
        config = self._config
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value
        self._save_config()
    
    def _save_config(self):
        """Save the current config to config.json"""
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
        
        try:
            with open(config_path, 'w') as f:
                json.dump(self._config, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get_admin_url(self) -> str:
        """Get the full URL of the admin server"""
        protocol = 'https' if self.get('admin.enable_ssl') else 'http'
        server_ip = self.get('admin.server_ip')
        server_port = self.get('admin.server_port')
        return f"{protocol}://{server_ip}:{server_port}"
    
    def is_lab_pi(self) -> bool:
        """Check if this device is configured as a Lab Pi"""
        # For now, we'll assume all devices except admin are Lab Pis
        return True
    
    def is_admin_pi(self) -> bool:
        """Check if this device is configured as the Admin Pi"""
        # For now, we'll check if server_ip is the local IP
        return self.get('admin.server_ip') == self._get_local_ip()
    
    def get_experiment_capabilities(self) -> list:
        """Get the list of experiment capabilities"""
        return self.get('lab.experiment_capabilities', [])
    
    def add_experiment_capability(self, experiment_id: int) -> None:
        """Add an experiment capability"""
        capabilities = self.get_experiment_capabilities()
        if experiment_id not in capabilities:
            capabilities.append(experiment_id)
            self.set('lab.experiment_capabilities', capabilities)
    
    def remove_experiment_capability(self, experiment_id: int) -> None:
        """Remove an experiment capability"""
        capabilities = self.get_experiment_capabilities()
        if experiment_id in capabilities:
            capabilities.remove(experiment_id)
            self.set('lab.experiment_capabilities', capabilities)
    
    def to_dict(self) -> dict:
        """Convert config to dictionary"""
        return self._config.copy()

# Singleton instance
config = Config()