#  VisionX – Phishing & Malicious Content Detection Platform

VisionX is a cybersecurity-focused web application designed to detect **phishing links, malicious emails, and dangerous files** using a **heuristic-based risk analysis engine**.  
The platform provides real-time scanning, persistent scan history, and professional security reports, making it ideal for **hackathons, demos, and security research projects**.

---

##  Features

-  URL phishing detection
-  Email content analysis
-  File risk scanning
-  Interactive security dashboard
-  Heuristic-based risk scoring (0–100)
-  Persistent scan history
-  Downloadable PDF security reports
-  CSV export for analysts
-  Modern dark-themed UI



##  Tools & Technologies

VisionX is built using a carefully selected tech stack to ensure **performance, security, and hackathon readiness**.

### 🔹 Backend

**Flask (Python)**  
  Lightweight backend framework used to build REST APIs for scanning URLs, emails, and files.

  **Flask-CORS**  
  Enables secure communication between the frontend and backend by allowing cross-origin requests.

  **SQLAlchemy (ORM)**  
  Handles database operations safely and efficiently without writing raw SQL.

  **SQLite**  
  A serverless, file-based database used to store scan history persistently.

---

### 🔹 Frontend

**HTML5**  
  Provides the structure for dashboards, tables, and scan pages.

**CSS3**  
  Used to design a modern, responsive, cybersecurity-themed interface.

**Vanilla JavaScript**  
  Handles API calls, dynamic UI updates, and dashboard logic without heavy frameworks.


### 🔹 Security & Detection Logic

**Heuristic-Based Scoring Engine**  
  Custom rule-based logic that evaluates URLs, emails, and files using suspicious keywords, HTTPS validation, file types, and behavioral indicators.

**Python Standard Libraries**
  - `hashlib` – SHA-256 hashing for files and domains  
  - `re` – Pattern detection  
  - `urllib.parse` – URL validation  
  - `random` – Simulated heuristic triggers  
  - `datetime` – Scan timestamping  


### 🔹 Reporting & Export

**ReportLab (PDF Generator)**  
  Generates professional, downloadable PDF security reports with risk levels and recommendations.

  **CSV Export Utility**  
  Allows exporting scan history for analysis in Excel, Google Sheets, or Power BI.


### 🔹 Development & Deployment

**Git & GitHub**  
  Version control, collaboration, and repository management.



##  How It Works

1. User submits a URL, email, or file
2. Backend analyzes input using heuristic rules
3. A risk score (0–100) and risk level are generated
4. Scan results are stored in the database
5. Results are displayed on the dashboard
6. Users can export reports as PDF or CSV


## Installation & Setup

```bash
# Clone the repository
git clone https://github.com/your-username/visionx.git

# Navigate to project directory
cd visionx

# Install dependencies
pip install flask flask-cors flask-sqlalchemy reportlab

# Run the application
python app.py
