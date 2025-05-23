from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Nomination(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    twitter_handle = db.Column(db.String(100), nullable=False)
    candidate = db.Column(db.String(100), nullable=False)
    reason = db.Column(db.Text)
    twitter_url = db.Column(db.String(200), nullable=False)
    monad_address = db.Column(db.String(42), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 için 45 karakter
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    discord_id = db.Column(db.String(50))
    discord_display_name = db.Column(db.String(100))

    def __repr__(self):
        return f'<Nomination {self.twitter_handle} -> {self.candidate}>'

class AllowedIP(db.Model):
    __tablename__ = "allowedIP"
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, unique=True)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)  # None ise süresiz izin

    def __repr__(self):
        return f'<AllowedIP {self.ip_address}>' 
        return f'<Nomination {self.twitter_handle} -> {self.candidate}>' 