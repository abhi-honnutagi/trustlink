from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import hashlib
import cv2
import pytesseract
import whois
import datetime
import socket
import requests

from db_config import connection

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = os.path.join(os.getcwd(),"uploads")

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# CLEAN DOMAIN

def clean_domain(url):

    domain = url.replace("http://","").replace("https://","")
    domain = domain.split("/")[0]
    domain = domain.replace("www.","")

    return domain

# URL ANALYSIS

def analyze_url(url):

    risk_score = 0
    domain_age = "Unknown"
    ip_address = "Unknown"
    ip_reputation = "Unknown"

    domain = clean_domain(url)

    # KEYWORD DETECTION
    keywords = [
        "login","bank","verify","secure","account",
        "update","reset","password","confirm",
        "security","alert","warning"
    ]

    for word in keywords:
        if word in url.lower():
            risk_score += 15

    # WHOIS CHECK

    try:

        w = whois.whois(domain)

        creation = w.creation_date

        if isinstance(creation,list):
            creation = creation[0]

        if creation:

            age_days = (datetime.datetime.now()-creation).days

            domain_age = str(age_days)+" days"

            if age_days < 30:
                risk_score += 40

    except:
        pass

    # RDAP FALLBACK

    if domain_age == "Unknown":

        try:

            url = "https://rdap.org/domain/"+domain
            r = requests.get(url,timeout=5)

            if r.status_code == 200:

                data = r.json()

                for event in data.get("events",[]):

                    if event.get("eventAction") == "registration":

                        date = event["eventDate"].split("T")[0]

                        creation = datetime.datetime.strptime(date,"%Y-%m-%d")

                        age_days = (datetime.datetime.now()-creation).days

                        domain_age = str(age_days)+" days"

                        if age_days < 30:
                            risk_score += 40

                        break

        except:
            domain_age = "Unavailable"

        if domain_age == "Unknown":
            domain_age = "Hidden (Private Domain)"

    # IP DETECTION

    try:

        ip_address = socket.gethostbyname(domain)

        suspicious_ranges = ["185.","103.","45.","192.168."]

        ip_reputation = "safe"

        for r in suspicious_ranges:
            if ip_address.startswith(r):
                ip_reputation = "danger"
                risk_score += 20

    except:
        ip_address = "Unknown"
        ip_reputation = "unknown"

    # FINAL RESULT

    if risk_score >= 70:
        result="danger"

    elif risk_score >= 40:
        result="warning"

    else:
        result="safe"

    trust_score = 100-risk_score

    return result,trust_score,domain_age,ip_address,ip_reputation


# URL SCAN API

@app.route("/scan-url",methods=["POST"])
def scan_url():

    data = request.json
    url = data["url"]

    result,trust_score,domain_age,ip,ip_rep = analyze_url(url)

    cursor = connection.cursor()

    cursor.execute("""
    INSERT INTO URL_SCANS
    (ID,URL,RESULT,TRUST_SCORE,SCAN_DATE)
    VALUES (URL_SCAN_SEQ.NEXTVAL,:1,:2,:3,SYSDATE)
    """,(url,result,trust_score))

    connection.commit()

    return jsonify({
        "result":result,
        "trust_score":trust_score,
        "domain_age":domain_age,
        "ip_address":ip,
        "ip_reputation":ip_rep
    })

# EMAIL SCAN

@app.route("/scan-email",methods=["POST"])
def scan_email():

    data=request.json
    email=data["email"]

    patterns=["urgent","verify","click","password","bank","login"]

    score=0

    for p in patterns:
        if p in email.lower():
            score+=1

    if score>=3:
        result="danger"
    elif score==2:
        result="warning"
    else:
        result="safe"

    cursor=connection.cursor()

    cursor.execute("""
    INSERT INTO EMAIL_SCANS
    (ID,EMAIL_TEXT,RESULT,SCAN_DATE)
    VALUES (EMAIL_SCAN_SEQ.NEXTVAL,:1,:2,SYSDATE)
    """,(email,result))

    connection.commit()

    return jsonify({"result":result})

# IMAGE SCAN

@app.route("/scan-image",methods=["POST"])
def scan_image():

    file=request.files["image"]

    path=os.path.join(UPLOAD_FOLDER,file.filename)
    file.save(path)

    img=cv2.imread(path)

    gray=cv2.cvtColor(img,cv2.COLOR_BGR2GRAY)

    text=pytesseract.image_to_string(gray)

    words=["verify","bank","login","password","click"]

    score=0

    for w in words:
        if w in text.lower():
            score+=1

    if score>=2:
        result="danger"
    elif score==1:
        result="warning"
    else:
        result="safe"

    cursor=connection.cursor()

    cursor.execute("""
    INSERT INTO IMAGE_SCANS
    (ID,IMAGE_NAME,RESULT,SCAN_DATE)
    VALUES (IMAGE_SCAN_SEQ.NEXTVAL,:1,:2,SYSDATE)
    """,(file.filename,result))

    connection.commit()

    return jsonify({"result":result,"detected_text":text})

# FILE SCAN

@app.route("/scan-file",methods=["POST"])
def scan_file():

    file=request.files["file"]

    path=os.path.join(UPLOAD_FOLDER,file.filename)
    file.save(path)

    sha256=hashlib.sha256()

    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(4096),b""):
            sha256.update(chunk)

    file_hash=sha256.hexdigest()

    result="safe"

    if file.filename.endswith((".exe",".bat",".js",".vbs",".scr")):
        result="suspicious"

    cursor=connection.cursor()

    cursor.execute("""
    INSERT INTO FILE_SCANS
    (ID,FILE_NAME,FILE_HASH,RESULT,SCAN_DATE)
    VALUES (FILE_SCAN_SEQ.NEXTVAL,:1,:2,:3,SYSDATE)
    """,(file.filename,file_hash,result))

    connection.commit()

    return jsonify({
        "file_name":file.filename,
        "file_hash":file_hash,
        "scan_result":result
    })

# DASHBOARD

@app.route("/dashboard-stats")
def dashboard():

    cursor=connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM URL_SCANS")
    urls=cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM EMAIL_SCANS")
    emails=cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM IMAGE_SCANS")
    images=cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM FILE_SCANS")
    files=cursor.fetchone()[0]

    return jsonify({
        "urls_scanned":urls,
        "emails_scanned":emails,
        "images_scanned":images,
        "files_scanned":files
    })

# HISTORY

@app.route("/scan-history")
def history():

    cursor = connection.cursor()

    history = []

    # URL history
    cursor.execute("SELECT URL, RESULT, SCAN_DATE FROM URL_SCANS")

    for row in cursor.fetchall():

        history.append({
            "type":"URL",
            "item":str(row[0]),
            "result":str(row[1]),
            "date":str(row[2])
        })

    # EMAIL history
    cursor.execute("SELECT EMAIL_TEXT, RESULT, SCAN_DATE FROM EMAIL_SCANS")

    for row in cursor.fetchall():

        history.append({
            "type":"EMAIL",
            "item":str(row[0]),
            "result":str(row[1]),
            "date":str(row[2])
        })

    # IMAGE history
    cursor.execute("SELECT IMAGE_NAME, RESULT, SCAN_DATE FROM IMAGE_SCANS")

    for row in cursor.fetchall():

        history.append({
            "type":"IMAGE",
            "item":str(row[0]),
            "result":str(row[1]),
            "date":str(row[2])
        })

    # FILE history
    cursor.execute("SELECT FILE_NAME, RESULT, SCAN_DATE FROM FILE_SCANS")

    for row in cursor.fetchall():

        history.append({
            "type":"FILE",
            "item":str(row[0]),
            "result":str(row[1]),
            "date":str(row[2])
        })

    return jsonify(history)



if __name__=="__main__":

    print("TrustLink Security Scanner Running")

    app.run(port=5000,debug=True)