# Webshell-detection
Created a cybersecurity web application that scans uploaded files for malware using the VirusTotal API, flags suspicious content, and maintains user-specific scan history.
# 🛡️ Webshell Detection - File Scanner

A lightweight cybersecurity web application that allows users to scan uploaded files for malware using the [VirusTotal API](https://www.virustotal.com/gui/home/upload). The app provides real-time analysis, categorizes threats (e.g., malicious, suspicious, harmless), and stores scan history per user.

## 🔒 Key Features

- 🔍 **File Upload and Scan**: Users can upload any file and scan it using VirusTotal.
- 🧠 **Threat Classification**: Scan results include categories like `malicious`, `suspicious`, `harmless`, and more.
- 🧾 **Scan History**: Logged-in users can view past scan results with timestamps and filenames.
- 🔐 **User Authentication**: Simple login system with email and password (hashed).
- 🧰 **Secure File Handling**: Files are processed and removed securely after scanning.
- 🌐 **Responsive Frontend**: Clean, modern UI for seamless user experience.

## 🛠️ Tech Stack

- **Frontend**: HTML, CSS, JavaScript (vanilla)
- **Backend**: Python (Flask)
- **API Integration**: VirusTotal Public API
- **Database**: MySQL
- **Authentication**: Simple login system (Flask + SQL)


📂 **Project Structure**
/project-root
├── templates/
│   ├── login.html
│   ├── index.html
│   └── history.html
├── static/
│   └── styles.css
├── app.py
├── .env
├── requirements.txt
└── README.md
