# 🛡️ Web Security Scanner

> **Live Now at:** [hackersgonnahack.pythonanywhere.com](https://hackersgonnahack.pythonanywhere.com)  
> Scan your websites for vulnerabilities in real-time with automated intelligence and sleek reporting dashboards.

A powerful, full-stack web application designed to perform **comprehensive security assessments** of websites. Analyze, detect, and track vulnerabilities with beautiful interactive reports and dashboards.

---

## ✨ Overview

**Web Security Scanner** is an automated vulnerability analysis tool focused on **web reconnaissance** and **active testing**. It helps developers and security enthusiasts understand the **security posture** of web applications by generating transparent and actionable reports.

> ✅ Ideal for bug bounty hunting, web developers, and cybersecurity learners.

---

## 📸 Live Preview

### 🔹 **🌐 Live Dashboard Example**
*View scan statistics, charts, and history.*

<img width="1280" height="800" alt="3" src="https://github.com/user-attachments/assets/a944ef73-a13f-479b-9fa8-a05f2cdd96f7" />


### 🔹 **Detailed Report View**
*See vulnerability details and past scan comparisons.*

<img width="1919" height="966" alt="image" src="https://github.com/user-attachments/assets/4dffcacc-c9d2-4242-a7a9-ec6d982cde7f" />
<img width="1919" height="966" alt="image" src="https://github.com/user-attachments/assets/96f2e2af-2e1b-41ce-924a-fe380b539a66" />
<img width="1919" height="875" alt="image" src="https://github.com/user-attachments/assets/f827ec77-fa27-4127-ad72-db51e67285f2" />

---

🚀 Key Features

🔍 **Automated Reconnaissance**

  * WHOIS, DNS (A, MX, TXT, etc.)
  * SSL Certificate Details
  * Subdomain Discovery (`crt.sh`)
  * HTTP Headers & Cookies
  * Technology Stack Detection

🛠️ **Vulnerability Testing**

  * SQL Injection
  * Cross-Site Scripting (XSS)
  * Open Redirect
  * Directory Traversal

📦 **Vulnerable JS Library Detection**

  * Scans for outdated or insecure frontend libraries.

📊 **Interactive Dashboard**

  * Security scores
  * Time-based scan trends
  * Filterable scan history

🧾 **Comprehensive Reporting**

  * HTML-based report view
  * Active modules & results log
  * Real-time scan status

📂 **Export Options**

  * Download reports in **PDF**, **CSV**, and **JSON** formats.

🔁 **Historical Tracking**

  * Compare current and past scan results
  * Highlights newly discovered or resolved issues

🧱 **Error-Resilient Architecture**

  * Fallback mechanisms for Nmap/socket scanning
  * Graceful handling of timeouts or network errors

---

🧰 Tech Stack

| Layer         | Tools & Libraries                                                             |
| ------------- | ----------------------------------------------------------------------------- |
| **Frontend**  | HTML, CSS, Bootstrap, Jinja2, JavaScript, Chart.js, date-fns                  |
| **Backend**   | Python, Flask, Flask-SQLAlchemy, Multiprocessing                              |
| **Database**  | SQLite via SQLAlchemy ORM                                                     |
| **Scanning**  | `requests`, `python-whois`, `python-nmap`, `dnspython`, `builtwith`, `crt.sh` |
| **Reporting** | `xhtml2pdf`, `pypdf`, `pyhanko`, `reportlab`, `csv`, `json`                   |

---

⚙️ Getting Started

🔑 Prerequisites

Make sure the following are installed:

* Python 3.x
* Git
* (Optional) Nmap for advanced port scanning

---

📦 Installation

Clone the repository
```bash
git clone https://github.com/TaniRawat/Web-Security-Scanner.git
cd Web-Security-Scanner
```

Create and activate a virtual environment
```bash
python -m venv venv
.\venv\Scripts\activate   # On Windows
# source venv/bin/activate   # On Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

---

▶️ Running the Application

```bash
python app.py
```

✅ Visit the app in your browser:
**[http://127.0.0.1:5050](http://127.0.0.1:5050)**

---

🧪 How to Use

1. Launch the app and enter a website URL (e.g., `https://example.com`).
2. Click **"Scan Now"**.
3. Wait for the scan to complete (dashboard will update).
4. Click **"View Report"** for detailed findings.
5. Use export buttons to download reports as **PDF**, **CSV**, or **JSON**.

---

🌐 Deployment

Want to make your scanner public?

* Deploy on **PythonAnywhere** *(great free tier for testing)*.
* Switch database to **PostgreSQL/MySQL** for production use.
* Use **Gunicorn** or **Waitress** for WSGI deployment.

---

👨‍💻 Author & Credits

**Tanishq Rawat**
(GitHub: https://github.com/TaniRawat)
Passionate about cybersecurity and full-stack development.

---

📄 License

This project is licensed under the [MIT License](./LICENSE).

---

⭐ Found this useful? Star the repo and share it!

