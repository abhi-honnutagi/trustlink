# TrustLink Security Scanner

TrustLink Security Scanner is a cybersecurity analysis platform that detects potential threats from URLs, emails, images, and files.

The system uses multiple security techniques such as domain intelligence, IP reputation analysis, OCR text extraction, and malware hash detection to identify malicious content.

This project helps users detect phishing attacks, suspicious links, and malware before interacting with them.

--------------------------------------------------

## Features

### URL Phishing Detection
Analyzes suspicious URLs using:
- Keyword analysis
- Domain age detection (WHOIS / RDAP)
- Server IP detection
- IP reputation checking

### Email Phishing Detection
Detects phishing emails by analyzing suspicious words such as:
- verify
- login
- password
- urgent
- bank

### Image Phishing Detection
Uses OCR (Optical Character Recognition) to extract text from images and detect phishing messages hidden inside screenshots.

### Malware File Detection
Detects malicious files using SHA-256 hashing and compares the hash with known malware signatures.

### Dashboard Analytics
Displays a dashboard showing the number of scans performed for:
- URLs
- Emails
- Images
- Files

### Scan History
Stores and displays all previous scans using an Oracle database.

--------------------------------------------------

## Technologies Used

Frontend
- HTML
- CSS
- JavaScript
- Chart.js

Backend
- Python
- Flask
- Flask-CORS

Cybersecurity Tools
- Tesseract OCR
- OpenCV
- WHOIS
- Socket Networking
- SHA-256 Hashing

Database
- Oracle Database

--------------------------------------------------

## System Architecture

User → Web Interface → Flask API → Threat Detection Engine → Oracle Database → Results Dashboard

Workflow:

1. User submits URL, email, image, or file.
2. Flask backend processes the request.
3. Security analysis is performed.
4. Results are returned to the frontend.
5. Scan results are stored in the database.

--------------------------------------------------

## Project Structure

trustlink-project

backend
- app.py
- db_config.py
- malware_dataset.py

frontend
- index.html
- style.css
- script.js

uploads

README.md

--------------------------------------------------

## Installation

Clone the repository

git clone https://github.com/yourusername/trustlink-security-scanner.git

Move into project directory

cd trustlink-security-scanner

Install required Python libraries

pip install flask flask-cors opencv-python pytesseract python-whois requests

Install Tesseract OCR

Download from:
https://github.com/UB-Mannheim/tesseract/wiki

Add the path inside the code

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

--------------------------------------------------

## Running the Project

Start the Flask server

python app.py

Open browser

http://127.0.0.1:5000

--------------------------------------------------

## Database Tables

URL_SCANS  
Stores scanned URLs and results

EMAIL_SCANS  
Stores scanned email messages

IMAGE_SCANS  
Stores scanned images

FILE_SCANS  
Stores scanned files

MALWARE_SIGNATURES  
Contains malware hash signatures

--------------------------------------------------

## Example Detection Methods

URL Detection
- Keyword analysis
- Domain age analysis
- IP reputation analysis

Image Detection
- OCR text extraction
- Phishing keyword scanning

File Detection
- SHA256 hash generation
- Malware signature comparison

--------------------------------------------------

## Security Techniques Used

- Multi-layer threat detection
- Domain intelligence analysis
- Network reputation checking
- OCR-based phishing detection
- Cryptographic hashing (SHA256)

--------------------------------------------------

## Future Improvements

Possible improvements include:

- Machine learning phishing detection
- Real IP reputation APIs
- Browser extension for real-time protection
- Integration with VirusTotal API
- Larger malware signature dataset

--------------------------------------------------

## Author

Project Name: TrustLink Security Scanner  
Domain: Cybersecurity Threat Detection System

--------------------------------------------------

## License

This project is created for educational and research purposes.
