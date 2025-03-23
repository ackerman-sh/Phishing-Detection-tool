# VirusTotal URL Scanner & AI Analysis Tool
This Flask-based web application allows users to scan URLs using **VirusTotal** and get an
**AI-generated security analysis** using the DeepSeek-R1 model.
---
## Features
- **Scan URLs** for potential threats using **VirusTotal API**.
- **Fetch analysis results** from VirusTotal.
- **AI-powered insights** based on the scan report.
- **Streamed AI responses** for real-time updates.
- **Error handling** for API failures and missing credentials.
---
## Installation
### 1. Clone the repository
```bash
git clone https://github.com/ackerman-sh/Pishing-Detection-tool.git
cd Pishing-Detection-tool
```
### 2. Run the installation script
```bash
chmod +x install.sh
./install.sh
```
---
## Configuration
### 1. Set up API keys
Create a file named `api.json` in the project directory and add your **VirusTotal** and **GitHub AI**
API keys:
```json
{
 "VIRUSTOTAL_API_KEY": "your_virustotal_api_key",
 "GITHUB_API_KEY": "your_github_api_key"
}
```
---
## Usage
### Start the Flask server:
```bash
source myenv/bin/activate
python app.py
```
### Access the Web Interface:
Open a browser and visit:
```bash
http://127.0.0.1:5000
```
