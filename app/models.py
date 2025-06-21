
from app.extensions import db
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash # Added generate_password_hash for completeness
import datetime
import uuid
import os
from flask import url_for


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')
    
    # Personal Information
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    name = db.Column(db.String(80), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    avatar_filename = db.Column(db.String(128), nullable=True)
    
    # Accessibility Information
    disabilities = db.Column(db.JSON, nullable=True)  # Stores a list of selected disabilities
    specific_disability = db.Column(db.Text, nullable=True)  # Detailed description of specific disability
    wheelchair_usage = db.Column(db.String(20), nullable=True)  # fulltime, parttime, or none
    assistive_tech = db.Column(db.Text, nullable=True)
    
    # Experience & Interests
    tech_experience = db.Column(db.String(20), nullable=True)
    interests = db.Column(db.JSON, nullable=True)  # Stores a list of selected interests
    
    # Communication Preferences
    email_notifications = db.Column(db.Boolean, default=True)
    newsletter_subscription = db.Column(db.Boolean, default=False)
    
    # Profile Picture
    profile_picture = db.Column(db.String(255), nullable=True)  # Store filename/path
    
    # Timestamps
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    # Password Reset
    reset_token = db.Column(db.String(100), nullable=True, index=True, unique=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)
    
    # Add relationship
    rsvps = db.relationship("RSVP", back_populates="user")
    is_admin = db.Column(db.Boolean, default=False, nullable=False) # New admin field

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

    def get_avatar_url(self):
        """Return the URL for the user's avatar image."""
        if self.avatar_filename:
            return url_for('static', filename='uploads/profiles/' + self.avatar_filename)
        return url_for('static', filename='uploads/profiles/default.png') # Assumes default.png is in uploads/profiles

    # Password hashing methods
    # set_password is not strictly needed if password is hashed upon assignment or in form processing
    # def set_password(self, password):
    #     self.password = generate_password_hash(password)

    def check_password(self, password_to_check):
        return check_password_hash(self.password, password_to_check)


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    contact_email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='company')
    approved = db.Column(db.Boolean, default=False)
    
    # Company Details
    phone = db.Column(db.String(20), nullable=True)
    website = db.Column(db.String(255), nullable=True)
    address = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text, nullable=True)
    industry = db.Column(db.String(50), nullable=True)
    company_size = db.Column(db.String(20), nullable=True)
    
    # Contact Person
    contact_name = db.Column(db.String(100), nullable=True)
    contact_title = db.Column(db.String(100), nullable=True)
    
    # Accessibility Information
    accessibility_experience = db.Column(db.String(50), nullable=True)
    compliance_requirements = db.Column(db.String(50), nullable=True)
    testing_timeline = db.Column(db.String(50), nullable=True)
    testing_budget = db.Column(db.String(50), nullable=True)
    
    # Products & Services
    products_services = db.Column(db.Text, nullable=True)
    accessibility_goals = db.Column(db.Text, nullable=True)
    interests = db.Column(db.JSON, nullable=True)  # Stores a list of selected interests
    
    # Timestamps
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password_to_check):
        return check_password_hash(self.password, password_to_check)

    def __repr__(self):
        return f'<Company {self.name}>'


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    def __repr__(self):
        return f'<Category {self.name}>'


class Event(db.Model):
    __tablename__ = "events"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(128), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False, index=True)
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=True)
    user_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=True)  # For user-created events
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)
    category = db.relationship('Category', backref='events')
    # Use dynamic loading so we can call ``event.rsvps.count()`` without
    # loading all related rows into memory.
    rsvps = db.relationship('RSVP', backref='event', lazy='dynamic')
    capacity = db.Column(db.Integer, nullable=True)
    waitlist = db.relationship('Waitlist', backref='event', lazy='dynamic')
    image_filename = db.Column(db.String(255), nullable=True) # Added for event images
    gift_card_amount_cents = db.Column(db.Integer, nullable=True, default=1000) # New field

    # Backwards compatibility for code that still references ``name``
    @property
    def name(self):
        return self.title

    @name.setter
    def name(self, value: str) -> None:
        self.title = value

    def __repr__(self):
        return f'<Event id={self.id} title="{self.title}">'


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.String, db.ForeignKey('events.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    user = db.relationship('User', backref='reviews')
    event = db.relationship('Event', backref='reviews')

    def __repr__(self):
        return f'<Review id={self.id} event_id="{self.event_id}" user_id="{self.user_id}" rating={self.rating}>'


class RSVP(db.Model):
    __tablename__ = "rsvps"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=False)
    event_id = db.Column(db.String, db.ForeignKey("events.id"), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    fulfilled = db.Column(db.Boolean, default=False)
    
    # Add relationships
    user = db.relationship("User", back_populates="rsvps")

    def __repr__(self):
        return f'<RSVP id={self.id} event_id="{self.event_id}" user_id="{self.user_id}">'


class Waitlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.String, db.ForeignKey('events.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    user = db.relationship('User', backref='waitlist_entries')

    def __repr__(self):
        return f'<Waitlist id={self.id} event_id="{self.event_id}" user_id="{self.user_id}">'


class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.String, db.ForeignKey('events.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    user = db.relationship('User', backref='favorites')
    event = db.relationship('Event', backref='favorited_by')

    def __repr__(self):
        return f'<Favorite id={self.id} event_id="{self.event_id}" user_id="{self.user_id}">'


class GiftCard(db.Model):
    __tablename__ = "gift_cards"
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=False)
    event_id = db.Column(db.String, db.ForeignKey("events.id"), nullable=False)
    amount_cents = db.Column(db.Integer, nullable=False)
    stripe_charge_id = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def __repr__(self):
        return f'<GiftCard id={self.id} event_id="{self.event_id}" user_id="{self.user_id}" amount_cents={self.amount_cents}>'


class Reward(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rsvp_id = db.Column(db.String, db.ForeignKey('rsvps.id'), nullable=False)
    code = db.Column(db.String(36), unique=True, nullable=False)
    value_cents = db.Column(db.Integer, nullable=False, default=1000)  # $10
    issued_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    redeemed = db.Column(db.Boolean, default=False)
    rsvp = db.relationship('RSVP', backref='reward', uselist=False)

    def __repr__(self):
        return f'<Reward id={self.id} rsvp_id="{self.rsvp_id}" code="{self.code}" value_cents={self.value_cents}>'


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
