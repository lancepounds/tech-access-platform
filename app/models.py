
from app.extensions import db
import datetime
import uuid


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')
    
    # Personal Information
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    
    # Accessibility Information
    disabilities = db.Column(db.Text, nullable=True)  # JSON string of selected disabilities
    assistive_tech = db.Column(db.Text, nullable=True)
    
    # Experience & Interests
    tech_experience = db.Column(db.String(20), nullable=True)
    interests = db.Column(db.Text, nullable=True)  # JSON string of selected interests
    
    # Communication Preferences
    email_notifications = db.Column(db.Boolean, default=True)
    newsletter_subscription = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    
    # Add relationship
    rsvps = db.relationship("RSVP", back_populates="user")

    def __repr__(self):
        return f'<User {self.email}>'
    
    @property
    def full_name(self):
        """Return the user's full name."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.last_name:
            return self.last_name
        return self.email.split('@')[0]  # Fallback to email username


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), default='company')
    approved = db.Column(db.Boolean, default=False)


class Event(db.Model):
    __tablename__ = "events"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    company_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=False)
    rsvps = db.relationship("RSVP", back_populates="event", cascade="all, delete-orphan")


class RSVP(db.Model):
    __tablename__ = "rsvps"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=False)
    event_id = db.Column(db.String, db.ForeignKey("events.id"), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    fulfilled = db.Column(db.Boolean, default=False)
    
    # Add relationships
    user = db.relationship("User", back_populates="rsvps")
    event = db.relationship("Event", back_populates="rsvps")


class GiftCard(db.Model):
    __tablename__ = "gift_cards"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=False)
    event_id = db.Column(db.String, db.ForeignKey("events.id"), nullable=False)
    amount_cents = db.Column(db.Integer, nullable=False)
    stripe_charge_id = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class Reward(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rsvp_id = db.Column(db.String, db.ForeignKey('rsvps.id'), nullable=False)
    code = db.Column(db.String(36), unique=True, nullable=False)
    value_cents = db.Column(db.Integer, nullable=False, default=1000)  # $10
    issued_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    redeemed = db.Column(db.Boolean, default=False)
    rsvp = db.relationship('RSVP', backref='reward', uselist=False)


class Check(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    interval_sec = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def __repr__(self):
        return f'<Check {self.name}>'


class CheckResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    check_id = db.Column(db.Integer, db.ForeignKey('check.id'), nullable=False)
    status = db.Column(db.Enum('up', 'down', name='check_status'), nullable=False)
    latency_ms = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    check = db.relationship('Check', backref='results')

    def __repr__(self):
        return f'<CheckResult {self.check_id} - {self.status}>'
