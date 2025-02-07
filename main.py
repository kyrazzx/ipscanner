import sys
import requests
import json
import shodan
import subprocess
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLineEdit, QLabel, QTextEdit, QProgressBar, QRadioButton, QButtonGroup
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# Insert your API keys
IPINFO_API_KEY = "IPINFO_KEY"
ABUSEIPDB_API_KEY = "ABUSEIPDB_KEY"
SHODAN_API_KEY = "SHODAN_KEY"
LEAKS_API_URL = "https://leak-lookup.com/api/search"
LEAKS_API_KEY = "LEAKSAPI_KEY"

class ScanThread(QThread):
    result_signal = pyqtSignal(str)
    
    def __init__(self, ip, is_ipv6):
        super().__init__()
        self.ip = ip
        self.is_ipv6 = is_ipv6
    
    def run(self):
        result_text = "Analysis in progress...\n"

        ipinfo_url = f"https://ipinfo.io/{self.ip}/json?token={IPINFO_API_KEY}"
        response = requests.get(ipinfo_url)
        if response.status_code == 200:
            data = response.json()
            result_text += f"IP: {data.get('ip', 'N/A')}\nCountry: {data.get('country', 'N/A')}\nRegion: {data.get('region', 'N/A')}\nCity: {data.get('city', 'N/A')}\nSupplier: {data.get('org', 'N/A')}\n"
        else:
            result_text += "Error retrieving IP information.\n"

        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={self.ip}"
        abuse_response = requests.get(abuse_url, headers=headers)
        if abuse_response.status_code == 200:
            abuse_data = abuse_response.json()
            result_text += f"\nAbuseIPDB:\nReputation score: {abuse_data['data']['abuseConfidenceScore']}%\n"
        else:
            result_text += "\nError checking AbuseIPDB.\n"

        try:
            shodan_api = shodan.Shodan(SHODAN_API_KEY)
            shodan_data = shodan_api.host(self.ip)
            result_text += "\nShodan Scan:\n"
            result_text += f"OS: {shodan_data.get('os', 'N/A')}\n"
            result_text += f"Open ports: {', '.join(map(str, shodan_data.get('ports', [])))}\n"
            result_text += f"Hosts: {', '.join(shodan_data.get('hostnames', []))}\n"
        except shodan.APIError:
            result_text += "\nError checking Shodan.\n"

        try:
            nmap_command = "nmap -6" if self.is_ipv6 else "nmap -F"
            nmap_result = subprocess.getoutput(f"{nmap_command} {self.ip}")
            result_text += f"\nNmap Scan:\n{nmap_result}\n"
        except Exception:
            result_text += "\nError during Nmap scan.\n"

        headers = {"Authorization": LEAKS_API_KEY}
        leak_response = requests.get(LEAKS_API_URL, headers=headers, params={"type": "ip", "query": self.ip})
        if leak_response.status_code == 200:
            leak_data = leak_response.json()
            if leak_data.get("found", False):
                result_text += "\nLeak Lookup:\nIP found in compromised databases!\n"
            else:
                result_text += "\nNo leaks found on Leak Lookup.\n"
        else:
            result_text += "\nError checking Leak Lookup.\n"
        
        self.result_signal.emit(result_text)

class OSINTTool(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle("IPScanner v1.1")
        self.setGeometry(100, 100, 600, 500)
        layout = QVBoxLayout()
        
        self.label = QLabel("Enter an IP address :")
        self.label.setFont(QFont("Arial", 12))
        layout.addWidget(self.label)
        
        self.inputField = QLineEdit(self)
        layout.addWidget(self.inputField)
        
        self.ipv4Radio = QRadioButton("IPv4")
        self.ipv6Radio = QRadioButton("IPv6")
        self.ipv4Radio.setChecked(True)
        
        self.radioGroup = QButtonGroup()
        self.radioGroup.addButton(self.ipv4Radio)
        self.radioGroup.addButton(self.ipv6Radio)
        
        layout.addWidget(self.ipv4Radio)
        layout.addWidget(self.ipv6Radio)
        
        self.scanButton = QPushButton("Analyze")
        self.scanButton.clicked.connect(self.scan_ip)
        layout.addWidget(self.scanButton)
        
        self.progressBar = QProgressBar()
        self.progressBar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.progressBar)
        
        self.resultArea = QTextEdit()
        self.resultArea.setReadOnly(True)
        layout.addWidget(self.resultArea)
        
        self.setLayout(layout)
    
    def scan_ip(self):
        ip = self.inputField.text().strip()
        if not ip:
            self.resultArea.setText("Please enter a valid IP address.")
            return
        
        is_ipv6 = self.ipv6Radio.isChecked()
        
        self.resultArea.setText("Analysis in progress...")
        self.progressBar.setValue(50)
        
        self.scan_thread = ScanThread(ip, is_ipv6)
        self.scan_thread.result_signal.connect(self.display_result)
        self.scan_thread.start()
    
    def display_result(self, result):
        self.resultArea.setText(result)
        self.progressBar.setValue(100)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = OSINTTool()
    window.show()
    sys.exit(app.exec())
