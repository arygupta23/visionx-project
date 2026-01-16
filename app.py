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

from flask import Flask, request, jsonify, send_from_directory, abort, send_file, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from io import BytesIO
import io
import csv

# -----------------------
# App configuration
# -----------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///visionx.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

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

with app.app_context():
    db.create_all()

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

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "bank", "password",
    "urgent", "click", "secure", "confirm"
]

# -----------------------
# Scoring logic
# -----------------------
def score_url(url: str):
    """
    Enhanced URL scoring:
    - keeps previous checks (length, HTTPS, suspicious keywords)
    - detects tracking/affiliate params (utm_ / aff / ref / track / clickid etc.)
    - penalizes long query strings and many query params
    - detects embedded redirectors and double-extensions in path
    - simulated low-reputation domain check (unchanged)
    """
    import urllib.parse

    reasons = []
    score = 0
    score = 0
    
    if len(url) > 75:
        score += 15
        reasons.append("Long URL")

    if not url.lower().startswith("https://"):
        score += 20
        reasons.append("No HTTPS")

    for w in SUSPICIOUS_WORDS:
        if w in url.lower():
            score += 10
            reasons.append(f"Suspicious keyword: {w}")

    domain = urlparse(url).netloc
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

    for w in SUSPICIOUS_WORDS:
        if w in content.lower():
            score += 10
            reasons.append(f"Suspicious phrase: {w}")

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

    if random.randint(1, 100) <= 5:
        score += 20
        reasons.append("Random heuristic triggered")

    return clamp(score), reasons, sha256

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
        "landing": "landing.html",
        "reports": "report.html",
        "dashboard": "dashboard.html",
        "history": "history.html",
        "scan": "scan.html",
        "settings": "settings.html",
        "access": "access.html",
        "home": "home.html",
        "about": "about.html"
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

