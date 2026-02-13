# -*- coding: utf-8 -*-

"""
VisionX - Phishing and Malicious Content Detection Platform
Single-file Flask backend (hackathon-ready)
"""

import os
import re
import json
import hashlib
import random
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, request, jsonify, send_from_directory, abort, send_file, redirect, session, url_for, g
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from io import BytesIO
import io
import socket
import csv
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

load_dotenv() # Load environment variables from .env

# -----------------------
# App configuration
# -----------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///visionx.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join("static", "avatars")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Google OAuth Config
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', 'placeholder-id')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', 'placeholder-secret')

oauth = OAuth(app)
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

CORS(app, resources={r"/api/*": {"origins": "*"}})

db = SQLAlchemy(app)

# -----------------------
# Database model
# -----------------------
class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(20), nullable=False)
    target = db.Column(db.String(1000), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)
    reasons = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_type": self.scan_type,
            "target": self.target,
            "risk_score": int(self.risk_score) if self.risk_score is not None else 0,
            "risk_level": self.risk_level,
            "reasons": json.loads(self.reasons) if self.reasons else [],
            "created_at": self.created_at.isoformat() + "Z"
        }

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default="Active")
    initials = db.Column(db.String(5))
    color = db.Column(db.String(20))
    email = db.Column(db.String(100))
    password_hash = db.Column(db.String(256)) # Stores the hashed password
    avatar = db.Column(db.String(200)) # Stores the filename

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "status": self.status,
            "initials": self.initials,
            "color": self.color,
            "color": self.color,
            "email": self.email or "",
            "avatar": self.avatar or ""
        }

with app.app_context():
    db.create_all()
    # Auto-migration for dev convenience: check if email column exists
    from sqlalchemy import text
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT email FROM user LIMIT 1"))
    except Exception:
        print("Migrating: Adding email column to user table...")
        try:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN email VARCHAR(100)"))
                conn.commit()
        except Exception as e:
            print(f"Migration failed: {e}")

    # Auto-migration: Check for avatar column
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT avatar FROM user LIMIT 1"))
    except Exception:
        print("Migrating: Adding avatar column to user table...")
        try:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN avatar VARCHAR(200)"))
                conn.commit()
        except Exception as e:
            print(f"Migration (Avatar) failed: {e}")

    # Auto-migration: Check for password_hash column
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT password_hash FROM user LIMIT 1"))
    except Exception:
        print("Migrating: Adding password_hash column to user table...")
        try:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN password_hash VARCHAR(256)"))
                
                # Set default password for existing users (admin123)
                default_pw = generate_password_hash("admin123")
                conn.execute(text(f"UPDATE user SET password_hash = :pw"), {"pw": default_pw})
                conn.commit()
        except Exception as e:
            print(f"Migration (Password) failed: {e}")

# -----------------------
# Helpers
# -----------------------
def clamp(score):
    return max(0, min(100, int(score)))

def risk_level(score):
    if score <= 30:
        return "Safe"
    if score <= 60:
        return "Suspicious"
    return "Dangerous"

def valid_url(url):
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False

def check_domain_exists(domain):
    """
    Verifies if a domain actually exists via DNS resolution.
    Returns True if exists, False otherwise.
    """
    try:
        # Set a short timeout for the DNS lookup
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(3.0)
        try:
            socket.gethostbyname(domain)
            return True
        finally:
            socket.setdefaulttimeout(original_timeout)
    except socket.error:
        return False

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "bank", "password",
    "urgent", "click", "secure", "confirm"
]

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "bank", "password",
    "urgent", "click", "secure", "confirm"
]

# -----------------------
# Scoring logic
# -----------------------
def score_url(url: str):
    """
    Enhanced URL scoring with real-world existence check.
    """
    import urllib.parse

    reasons = []
    score = 0
    
    # 1. Length Check
    if len(url) > 75:
        score += 15
        reasons.append("Long URL")

    # 2. Protocol Check
    if not url.lower().startswith("https://"):
        score += 35
        reasons.append("No HTTPS (Insecure)")

    # 3. Keyword Check
    for w in SUSPICIOUS_WORDS:
        if w in url.lower():
            score += 10
            reasons.append(f"Suspicious keyword: {w}")

    # 4. Domain Existence Check (Real World)
    domain = urlparse(url).netloc
    # Strip port if present for DNS check
    dns_domain = domain.split(':')[0]
    
    if not check_domain_exists(dns_domain):
        score += 100 # Immediate Danger/Block
        reasons.append(f"Domain '{dns_domain}' does not exist (DNS lookup failed)")
    else:
        # Only do reputation check if domain actually exists
        h = int(hashlib.sha256(domain.encode()).hexdigest(), 16)
        if h % 10 < 3:
            score += 25
            reasons.append("Low reputation domain (simulated)")

    return clamp(score), reasons

def score_email(sender, content):
    score = 0
    reasons = []

    if "@" not in sender:
        score += 30
        reasons.append("Invalid sender address")
    else:
        # Check domain existence for email
        domain = sender.split('@')[-1]
        if not check_domain_exists(domain):
            score += 100
            reasons.append(f"Email domain '{domain}' does not exist (DNS lookup failed)")

    for w in SUSPICIOUS_WORDS:
        if w in content.lower():
            score += 10
            reasons.append(f"Suspicious phrase: {w}")

    # Extract and scan URLs in content
    # Regex to find http/https URLs
    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*', content)
    
    if urls:
        for url in urls:
            url_score, url_reasons = score_url(url)
            if url_score > 0:
                score += url_score
                # Add context to reasons
                for r in url_reasons:
                    reasons.append(f"Link '{url}': {r}")

    return clamp(score), reasons

def score_file(filename, data):
    score = 0
    reasons = []

    sha256 = hashlib.sha256(data).hexdigest()

    if filename.lower().endswith((".exe", ".bat", ".js")):
        score += 40
        reasons.append("Executable file")

    if len(data) < 1024:
        score += 10
        reasons.append("Very small file")
        
    # Attempt to scan content for URLs if it looks like text
    try:
        # Try decoding as UTF-8 to see if it's a text file
        text_content = data.decode('utf-8')
        
        # Regex to find http/https URLs
        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*', text_content)
        
        if urls:
            for url in urls:
                url_score, url_reasons = score_url(url)
                if url_score > 0:
                    score += url_score
                    for r in url_reasons:
                        reasons.append(f"Linked URL '{url}': {r}")
                        
    except UnicodeDecodeError:
        # Not a text file (binary), skip checking content for links
        pass

    return clamp(score), reasons, sha256

# -----------------------
# Auth & Middleware
# -----------------------
@app.before_request
def auth_middleware():
    # Allow static resources
    if request.path.startswith('/static'):
        return None
        
    # Whitelist login routes
    if request.path in ['/ui/login', '/api/login', '/api/login/google', '/api/login/google/callback']:
        return None
        
    # Load user if session exists
    user_id = session.get('user_id')
    if user_id:
        g.user = User.query.get(user_id)
    else:
        g.user = None
        
    # Protect /ui routes
    if request.path.startswith('/ui/'):
        if not g.user:
            return redirect('/ui/login')
            
    # Protect /api routes (except auth ones)
    if request.path.startswith('/api/'):
        if not g.user:
            return jsonify({"error": "Unauthorized"}), 401

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username") # Can be email or name
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
        
    # Try finding by name or email
    user = User.query.filter(
        (User.name == username) | (User.email == username)
    ).first()
    
    if user and user.password_hash and check_password_hash(user.password_hash, password):
        session['user_id'] = user.id
        return jsonify({"message": "Logged in", "user": user.to_dict()})
        
    return jsonify({"error": "Invalid username or password"}), 401

@app.route("/api/login/google")
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/api/login/google/callback")
def google_callback():
    try:
        token = oauth.google.authorize_access_token()
        user_info = token.get('userinfo')
        # If userinfo is not directly in the token response (depends on provider config), fetch it:
        if not user_info:
             user_info = oauth.google.userinfo()
             
        email = user_info.get('email')
        name = user_info.get('name', 'Google User')
        
        if not email:
            return jsonify({"error": "Google account has no email"}), 400
            
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Create new user
            parts = [n for n in name.strip().split(" ") if n]
            initials = "".join([n[0] for n in parts[:2]]).upper() if parts else "??"
            colors = ["bg-primary", "bg-purple-500", "bg-success", "bg-warning", "bg-pink-500", "bg-indigo-500"]
            
            user = User(
                name=name,
                email=email,
                role="Analyst",
                status="Active",
                initials=initials,
                color=random.choice(colors),
                password_hash="google_oauth" # Placeholder
            )
            db.session.add(user)
            db.session.commit()
            
        session['user_id'] = user.id
        return redirect('/ui/home')
        
    except Exception as e:
        app.logger.error(f"Google login failed: {e}")
        # Redirect mostly to show error, or return JSON if strictly API usage intended (but this is browser flow)
        return redirect('/ui/login#error')

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    
    if not name or not email or not password:
        return jsonify({"error": "All fields are required"}), 400
        
    # Check if user exists
    if User.query.filter((User.email == email) | (User.name == name)).first():
        return jsonify({"error": "User already exists"}), 409
        
    # Create new user
    parts = [n for n in name.strip().split(" ") if n]
    initials = "".join([n[0] for n in parts[:2]]).upper() if parts else "??"
    colors = ["bg-primary", "bg-purple-500", "bg-success", "bg-warning", "bg-pink-500", "bg-indigo-500"]
    
    new_user = User(
        name=name,
        email=email,
        role="Analyst", # Default role
        status="Active",
        initials=initials,
        color=random.choice(colors),
        password_hash=generate_password_hash(password)
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    # Auto-login
    session['user_id'] = new_user.id
    
    return jsonify({"message": "Registered successfully", "user": new_user.to_dict()})

@app.route("/api/me", methods=["GET"])
def get_current_user():
    if not g.user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(g.user.to_dict())

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})



# -----------------------
# UI lookup and routes
# -----------------------
def find_ui_file(filename: str):
    """
    Robust lookup for shipped HTML files. Returns (directory, filename) if found, else (None, None).
    Search order:
      - VISIONX_UI_ROOT env var (if set)
      - VISIONX_UI_ROOT env var (if set)
      - VISIONX_UI_ROOT env var (if set)
          - directory of this module
      - current working directory
      - common repo relative locations (useful when running from IDE with different cwd)
    """
    module_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(module_dir, filename),
        os.path.join(os.getcwd(), filename),
        os.path.join(module_dir, "static", filename),
        os.path.join(module_dir, "..", "source", "repos", filename),
        os.path.join(module_dir, "..", filename),
        os.path.join(module_dir, "templates", filename),
    ]
    for path in candidates:
        if os.path.exists(path):
            return os.path.dirname(path), os.path.basename(path)
    return None, None

@app.route("/", methods=["GET"])
def index():
    # Direct access to the application hub, skipping the landing page.
    return redirect("/ui/home")

@app.route("/ui/<page>", methods=["GET"])
def ui_page(page):
    """
    Serve simple UI HTML files shipped in the repository.
    """
    mapping = {
        "login": "login.html",
        "landing": "landing.html",
        "reports": "report.html",
        "dashboard": "dashboard.html",
        "history": "history.html",
        "scan": "scan.html",
        "settings": "settings.html",
        "access": "access.html",
        "home": "home.html",
        "about": "about.html",
        "profile": "profile.html"
    }
    fname = mapping.get(page)
    if not fname:
        abort(404)
    dirpath, realfname = find_ui_file(fname)
    if dirpath:
        app.logger.info("Serving %s from %s", realfname, dirpath)
        return send_from_directory(dirpath, realfname)
    app.logger.warning("UI file %s not found (looked in multiple locations)", fname)
    abort(404)

# Added route to serve ui/index.html from a ui directory
@app.route("/ui", methods=["GET"])
def serve_ui():
    # This will serve the file located at ./ui/index.html relative to the process working directory.
    # Ensure a folder named 'ui' containing 'index.html' exists, or set VISIONX_UI_ROOT and keep find_ui_file logic.
    ui_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")
    if os.path.exists(os.path.join(ui_dir, "index.html")):
        app.logger.info("Serving UI index from %s", ui_dir)
        return send_from_directory(ui_dir, "index.html")
    # Fallback: try find_ui_file for index.html location
    dirpath, fname = find_ui_file("index.html")
    if dirpath:
        app.logger.info("Serving UI index from discovered path %s", dirpath)
        return send_from_directory(dirpath, fname)
    app.logger.warning("ui/index.html not found; returning JSON hint")
    return jsonify({"message": "UI index not found on disk. Place index.html under ./ui or set VISIONX_UI_ROOT."}), 404

# -----------------------
# API endpoints
# -----------------------
@app.route("/api/scan/url", methods=["POST"])
def scan_url():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not valid_url(url):
        return jsonify({"error": "Invalid URL"}), 400

    score, reasons = score_url(url)
    level = risk_level(score)

    record = ScanHistory(
        scan_type="URL",
        target=url,
        risk_score=score,
        risk_level=level,
        reasons=json.dumps(reasons)
    )
    db.session.add(record)
    db.session.commit()

    return jsonify(record.to_dict())

@app.route("/api/scan/email", methods=["POST"])
def scan_email():
    data = request.get_json()
    sender = data.get("sender", "")
    content = data.get("content", "")

    score, reasons = score_email(sender, content)
    level = risk_level(score)

    record = ScanHistory(
        scan_type="EMAIL",
        target=sender,
        risk_score=score,
        risk_level=level,
        reasons=json.dumps(reasons)
    )
    db.session.add(record)
    db.session.commit()

    return jsonify(record.to_dict())

@app.route("/api/scan/file", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "File required"}), 400

    f = request.files["file"]
    data = f.read()

    score, reasons, sha256 = score_file(f.filename, data)
    level = risk_level(score)

    record = ScanHistory(
        scan_type="FILE",
        target=f.filename,
        risk_score=score,
        risk_level=level,
        reasons=json.dumps(reasons)
    )
    db.session.add(record)
    db.session.commit()

    return jsonify(record.to_dict())

@app.route("/api/history", methods=["GET"])
def history():
    items = ScanHistory.query.order_by(ScanHistory.created_at.desc()).all()
    return jsonify([i.to_dict() for i in items])

@app.route("/api/history/<int:id>", methods=["DELETE"])
def delete_history_item(id):
    record = ScanHistory.query.get(id)
    if not record:
        return jsonify({"error": "Record not found"}), 404
    
    db.session.delete(record)
    db.session.commit()
    return jsonify({"message": "Record deleted successfully"})

@app.route("/api/history/export/csv", methods=["GET"])
def export_history_csv():
    """Generates a CSV of all scan history and returns it as a downloadable file."""
    records = ScanHistory.query.order_by(ScanHistory.created_at.desc()).all()
    
    # Create CSV in memory
    si = BytesIO()
    # Use TextIOWrapper to handle string writing for csv module
    cw = csv.writer(pd := io.TextIOWrapper(si, encoding='utf-8', write_through=True))
    
    # Headers
    cw.writerow(["Scan ID", "Scan Type", "Target", "Risk Score", "Risk Level", "Timestamp", "Detail Reasons"])
    
    # Data
    for r in records:
        cw.writerow([
            r.id, 
            r.scan_type, 
            r.target, 
            r.risk_score, 
            r.risk_level, 
            r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            r.reasons
        ])
    
    si.seek(0)
    
    # Flask send_file requires bytes for BytesIO, but CSV writer wraps text.
    output = BytesIO()
    output.write(b'\xef\xbb\xbf') # BOM
    output.write(si.getvalue())
    output.seek(0)

    return send_file(
        output,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"visionx_scan_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )

@app.route("/api/users", methods=["GET"])
def get_users():
    users = User.query.all()
    # If no users exist, seed default ones
    if not users:
        default_pw = generate_password_hash("admin123")
        seed_users = [
            User(name="Admin User", role="Administrator", status="Active", initials="AC", color="bg-primary", password_hash=default_pw),
            User(name="John Doe", role="Analyst", status="Active", initials="JD", color="bg-purple-500", password_hash=default_pw)
        ]
        db.session.add_all(seed_users)
        db.session.commit()
        users = User.query.all()
        
    return jsonify([u.to_dict() for u in users])

@app.route("/api/users", methods=["POST"])
def create_user():
    data = request.get_json()
    name = data.get("name")
    role = data.get("role")
    email = data.get("email", "")
    
    if not name or not role:
        return jsonify({"error": "Name and Role required"}), 400
        
    parts = [n for n in name.strip().split(" ") if n]
    initials = "".join([n[0] for n in parts[:2]]).upper() if parts else "??"
    colors = ["bg-primary", "bg-purple-500", "bg-success", "bg-warning", "bg-pink-500", "bg-indigo-500"]
    color = random.choice(colors)
    
    user = User(name=name, role=role, status="Active", initials=initials, color=color, email=email)
    db.session.add(user)
    db.session.commit()
    
    return jsonify(user.to_dict()), 201

@app.route("/api/users/<int:id>", methods=["PUT"])
def update_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    if data:
        user.name = data.get("name", user.name)
        user.role = data.get("role", user.role)
        user.status = data.get("status", user.status)
        user.email = data.get("email", user.email)
        
        # Regenerate initials if name changes
        if "name" in data:
            user.initials = "".join([n[0] for n in user.name.split(" ")[:2]]).upper()

    db.session.commit()
    return jsonify(user.to_dict())

@app.route("/api/users/<int:id>/avatar", methods=["POST"])
def upload_avatar(id):
    user = User.query.get(id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if 'avatar' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    if file:
        from werkzeug.utils import secure_filename
        filename = secure_filename(f"user_{id}_{int(datetime.now().timestamp())}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Save relative path for frontend usage
        user.avatar = f"/static/avatars/{filename}"
        db.session.commit()
        
        return jsonify({"avatar": user.avatar})

    return jsonify({"error": "Upload failed"}), 500

@app.route("/api/users/<int:id>", methods=["DELETE"])
def delete_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({"error": "User not found"}), 404
        
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted"})

# -----------------------
# Report generation
# -----------------------
from reportlab.lib import colors

# -----------------------
# Report generation
# -----------------------
@app.route("/api/report/<int:scan_id>", methods=["GET"])
def generate_report(scan_id):
    scan = ScanHistory.query.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan record not found"}), 404

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # Header Background - Dark Teal/Blue
    p.setFillColorRGB(0.06, 0.12, 0.13) # #111e21
    p.rect(0, height - 100, width, 100, fill=1)

    # Title - Cyan/Primary
    p.setFillColorRGB(0.1, 0.76, 0.9) # #19c3e6
    p.setFont("Helvetica-Bold", 24)
    p.drawString(50, height - 60, "VisionX Security Scan Report")

    p.setFillColor(colors.white)
    p.setFont("Helvetica", 10)
    p.drawString(50, height - 85, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

    # Reset to black for body
    p.setFillColor(colors.black)

    # Scan Details Section
    y = height - 140
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "Scan Details")
    p.line(50, y - 5, 200, y - 5)
    
    y -= 30
    p.setFont("Helvetica", 12)
    p.drawString(50, y, f"Scan ID: {scan.id}")
    y -= 20
    p.drawString(50, y, f"Target: {scan.target}")
    y -= 20
    p.drawString(50, y, f"Scan Type: {scan.scan_type}")
    
    # Risk Assessment Section
    y -= 40
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "Risk Assessment")
    p.line(50, y - 5, 200, y - 5)

    y -= 30
    p.setFont("Helvetica", 12)
    p.drawString(50, y, "Risk Score:")
    p.drawString(130, y, f"{scan.risk_score} / 100")
    
    y -= 20
    p.drawString(50, y, "Risk Level:")
    
    # Color-coded Risk Level
    if scan.risk_level == "Dangerous":
        p.setFillColorRGB(0.88, 0.3, 0.3) # Red
    elif scan.risk_level == "Suspicious":
        p.setFillColorRGB(1.0, 0.84, 0.2) # Orange/Gold
    else:
        p.setFillColorRGB(0.3, 0.88, 0.3) # Green
        
    p.setFont("Helvetica-Bold", 12)
    p.drawString(130, y, scan.risk_level.upper())
    p.setFillColor(colors.black) # Reset

    # Why this was flagged
    y -= 50
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "Findings & Analysis")
    p.line(50, y - 5, 200, y - 5)
    
    y -= 25
    p.setFont("Helvetica", 11)
    reasons = json.loads(scan.reasons) if scan.reasons else []
    if reasons:
        for r in reasons:
            p.drawString(60, y, f"• {r}")
            y -= 18
    else:
        p.drawString(60, y, "No specific threats detected.")
        y -= 18

    # Recommended Actions
    y -= 30
    p.setFont("Helvetica-Bold", 14)
    p.setFillColorRGB(0.1, 0.76, 0.9) # Primary color for header
    p.drawString(50, y, "Recommended Actions")
    p.setFillColor(colors.black)
    
    y -= 25
    p.setFont("Helvetica", 11)

    if scan.risk_level == "Dangerous":
        p.drawString(60, y, "1. BLOCK this entity immediately in your firewall/gateway.")
        y -= 18
        p.drawString(60, y, "2. Do NOT interact or provide credentials.")
        y -= 18
        p.drawString(60, y, "3. Isolate any systems that may have accessed this target.")
    elif scan.risk_level == "Suspicious":
        p.drawString(60, y, "1. Treat with EXTREME CAUTION.")
        y -= 18
        p.drawString(60, y, "2. Verify the source through an alternative channel.")
        y -= 18
        p.drawString(60, y, "3. Do not download any attachments.")
    else:
        p.drawString(60, y, "1. No immediate action required based on current threat intel.")
        y -= 18
        p.drawString(60, y, "2. Standard security practices apply.")

    # Footer
    p.setFont("Helvetica-Oblique", 9)
    p.setFillColor(colors.gray)
    p.drawString(50, 30, "Confidential Property of VisionX Security Systems.")
    p.drawRightString(width - 50, 30, f"Page 1 of 1")

    p.showPage()
    p.save()

    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"visionx_report_{scan_id}.pdf",
        mimetype="application/pdf"
    )

# -----------------------
# Run app
# -----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

def find_ui_file(filename: str):
    """
    Robust lookup for shipped HTML files. Returns (directory, filename) if found, else (None, None).
    Search order:
      - VISIONX_UI_ROOT env var (if set)
      - directory of this module
      - current working directory
      - common repo relative locations
    """
    # Respect explicit env var first
    ui_root = os.environ.get("VISIONX_UI_ROOT")
    if ui_root:
        candidate = os.path.join(ui_root, filename)
        if os.path.exists(candidate):
            return os.path.abspath(ui_root), os.path.basename(candidate)

    module_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(module_dir, filename),
        os.path.join(os.getcwd(), filename),
        os.path.join(module_dir, "static", filename),
        os.path.join(module_dir, "..", "source", "repos", filename),
        os.path.join(module_dir, "..", filename),
        os.path.join(module_dir, "templates", filename),
    ]
    for path in candidates:
        if os.path.exists(path):
            return os.path.dirname(os.path.abspath(path)), os.path.basename(path)
    return None, None

