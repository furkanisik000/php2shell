"""ASP.NET-like mock target with XXE + path traversal vulnerabilities."""
import os
import re
import xml.etree.ElementTree as ET
from flask import Flask, request, make_response

app = Flask(__name__)

@app.route("/api/xml", methods=["POST", "GET"])
def xxe_endpoint():
    """XXE-vulnerable XML endpoint (simulates .NET XmlDocument with external entities)."""
    xml_data = request.form.get("xml") or request.args.get("xml") or request.data.decode("utf-8", "replace")
    if not xml_data:
        return "xml param required", 400
    
    # Vulnerable: parse XML with external entity processing
    # In real .NET, XmlDocument with DTD processing would read the file
    try:
        # Extract XXE payload and read the file (simulating .NET behavior)
        match = re.search(r'SYSTEM\s+"file://([^"]+)"', xml_data)
        if match:
            file_path = match.group(1)
            if os.path.exists(file_path):
                with open(file_path, "r", errors="replace") as f:
                    content = f.read()
                return f"<result>{content}</result>"
            else:
                return f"<error>File not found: {file_path}</error>", 404
        else:
            # Parse normally if no XXE
            root = ET.fromstring(xml_data)
            return f"<result>parsed: {root.tag}</result>"
    except Exception as e:
        return f"<error>{str(e)}</error>", 500

@app.route("/read", methods=["GET", "POST"])
def lfi_endpoint():
    """Path traversal LFI endpoint (simulates .NET file read without sanitization)."""
    file_param = request.args.get("file") or request.form.get("file") or ""
    if not file_param:
        return "file param required", 400
    
    # Vulnerable: no path sanitization
    if ".." in file_param or file_param.startswith("/"):
        # Read the file directly (simulating .NET behavior)
        if os.path.exists(file_param):
            with open(file_param, "r", errors="replace") as f:
                return f.read()
        else:
            return f"File not found: {file_param}", 404
    else:
        return "Invalid path", 400

@app.route("/health")
def health():
    return "dotnet-mock-ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
