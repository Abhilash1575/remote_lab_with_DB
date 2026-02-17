from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
import re

db = SQLAlchemy()
bcrypt = Bcrypt()

# Password policy constants
MIN_PASSWORD_LENGTH = 8
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_NUMBER = True
REQUIRE_SPECIAL = True
PASSWORD_EXPIRY_DAYS = 90

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))
    is_admin = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True)
    
    # Relationships
    bookings = db.relationship('Booking', backref='user', lazy=True)
    sessions = db.relationship('Session', backref='user', lazy=True)
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        # Validate password against policy
        if not self.validate_password(password):
            raise ValueError('Password does not meet security requirements')
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.password_changed_at = datetime.utcnow()
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    @staticmethod
    def validate_password(password):
        # Check minimum length
        if len(password) < MIN_PASSWORD_LENGTH:
            return False
        
        # Check character requirements
        if REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            return False
        
        if REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            return False
        
        if REQUIRE_NUMBER and not any(c.isdigit() for c in password):
            return False
        
        if REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        
        return True
    
    def is_password_expired(self):
        if self.password_changed_at is None:
            return True
        return datetime.utcnow() - self.password_changed_at > timedelta(days=PASSWORD_EXPIRY_DAYS)
    
    def __repr__(self):
        return f'<User {self.email}>'

class Experiment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    max_duration = db.Column(db.Integer, nullable=False, default=60)  # in minutes
    price = db.Column(db.Float, default=0.0)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    bookings = db.relationship('Booking', backref='experiment', lazy=True)
    
    def __repr__(self):
        return f'<Experiment {self.name}>'

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    experiment_id = db.Column(db.Integer, db.ForeignKey('experiment.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='UPCOMING')  # UPCOMING, ACTIVE, IN_PROGRESS, COMPLETED, EXPIRED, CANCELLED
    session_key = db.Column(db.String(20), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # Relationships
    session = db.relationship('Session', backref='booking', uselist=False)
    
    def __repr__(self):
        return f'<Booking {self.session_key}>'

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('booking.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_key = db.Column(db.String(20), unique=True, nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # in minutes
    ip_address = db.Column(db.String(45))
    mac_address = db.Column(db.String(17))
    status = db.Column(db.String(20), default='ACTIVE')  # ACTIVE, EXPIRED, TERMINATED
    
    def __repr__(self):
        return f'<Session {self.session_key}>'

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=True, nullable=False)
    ip_address = db.Column(db.String(45))
    device_name = db.Column(db.String(100), nullable=False)
    device_type = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100))
    status = db.Column(db.String(20), default='OFFLINE')  # ONLINE, OFFLINE, MAINTENANCE, BUSY
    last_seen = db.Column(db.DateTime)
    last_heartbeat = db.Column(db.DateTime)
    firmware_version = db.Column(db.String(20))
    hardware_version = db.Column(db.String(20))
    
    # Experiment capabilities
    experiment_capabilities = db.Column(db.Text)  # JSON string of supported experiment IDs
    
    # Current assignment
    current_booking_id = db.Column(db.Integer, db.ForeignKey('booking.id'))
    current_session_id = db.Column(db.Integer, db.ForeignKey('session.id'))
    
    # Monitoring fields
    cpu_usage = db.Column(db.Float)  # Percentage
    ram_usage = db.Column(db.Float)  # Percentage
    temperature = db.Column(db.Float)  # Celsius
    battery_level = db.Column(db.Float)  # Percentage
    battery_voltage = db.Column(db.Float)  # Volts
    ac_status = db.Column(db.Boolean)  # True if AC power is connected
    charging_status = db.Column(db.Boolean)  # True if battery is charging
    maintenance_mode = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<Device {self.device_name}>'
    
    def get_experiment_capabilities(self):
        """Get list of experiment IDs this device supports"""
        if self.experiment_capabilities:
            try:
                import json
                return json.loads(self.experiment_capabilities)
            except:
                pass
        return []
    
    def set_experiment_capabilities(self, capabilities):
        """Set list of experiment IDs this device supports"""
        import json
        self.experiment_capabilities = json.dumps(capabilities)
    
    def add_experiment_capability(self, experiment_id):
        """Add an experiment capability to this device"""
        capabilities = self.get_experiment_capabilities()
        if experiment_id not in capabilities:
            capabilities.append(experiment_id)
            self.set_experiment_capabilities(capabilities)
    
    def remove_experiment_capability(self, experiment_id):
        """Remove an experiment capability from this device"""
        capabilities = self.get_experiment_capabilities()
        if experiment_id in capabilities:
            capabilities.remove(experiment_id)
            self.set_experiment_capabilities(capabilities)
    
    def is_available(self):
        """Check if device is available for new experiment"""
        return self.status == 'ONLINE' and not self.maintenance_mode and self.current_booking_id is None
    
    def is_heartbeat_expired(self, timeout=10):
        """Check if heartbeat has expired (in seconds)"""
        if not self.last_heartbeat:
            return True
        from datetime import datetime
        delta = datetime.utcnow() - self.last_heartbeat
        return delta.total_seconds() > timeout

class DeviceMetric(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_usage = db.Column(db.Float)
    ram_usage = db.Column(db.Float)
    temperature = db.Column(db.Float)
    battery_level = db.Column(db.Float)
    battery_voltage = db.Column(db.Float)
    ac_status = db.Column(db.Boolean)
    charging_status = db.Column(db.Boolean)
    
    # Relationships
    device = db.relationship('Device', backref='metrics', lazy=True)
    
    def __repr__(self):
        return f'<DeviceMetric device_id={self.device_id} timestamp={self.timestamp}>'

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    level = db.Column(db.String(10), default='INFO')  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    category = db.Column(db.String(50), default='SYSTEM')  # SYSTEM, EXPERIMENT, ERROR, SSH
    message = db.Column(db.Text, nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    device = db.relationship('Device', backref='logs', lazy=True)
    user = db.relationship('User', backref='logs', lazy=True)
    
    def __repr__(self):
        return f'<SystemLog {self.level}: {self.message}>'

class OTAUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    firmware_version = db.Column(db.String(20), nullable=False)
    firmware_path = db.Column(db.String(255), nullable=False)
    update_status = db.Column(db.String(20), default='PENDING')  # PENDING, DOWNLOADING, INSTALLING, COMPLETED, FAILED
    error_message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<OTAUpdate {self.firmware_version}>'

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    def __init__(self, user_id, token, expires_in=3600):
        self.user_id = user_id
        self.token = token
        self.expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
    
    def is_expired(self):
        return datetime.utcnow() > self.expires_at
    
    def __repr__(self):
        return f'<PasswordResetToken {self.token}>'