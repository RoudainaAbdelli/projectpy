import sys
import nmap
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit

class PortScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('Scan de Ports et Service')
        self.setGeometry(100, 100, 600, 400)
        
        layout = QVBoxLayout()
        
        self.ip_range_label = QLabel('Entrez une plage d\'adresses IP :')
        layout.addWidget(self.ip_range_label)
        
        self.ip_range_input = QLineEdit()
        layout.addWidget(self.ip_range_input)
        
        self.scan_button = QPushButton('Scanner')
        self.scan_button.clicked.connect(self.scan_ports)
        layout.addWidget(self.scan_button)
        
        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        layout.addWidget(self.results_area)
        
        self.setLayout(layout)
    
    def scan_ports(self):
        ip_range = self.ip_range_input.text()
        self.results_area.clear()
        
        nm = nmap.PortScanner()
        try:
            nm.scan(ip_range, arguments='-sS -Pn -T4 -p 1-1000') 

            for host in nm.all_hosts(): 
             self.results_area.append(f"Host: {host} ({nm[host].hostname()})") 
             self.results_area.append(f"State: {nm[host].state()}") 

            for protocol in nm[host].all_protocols(): 
                self.results_area.append(f"\nProtocol: {protocol}") 

                ports = nm[host][protocol].keys() 
                for port in ports: 
                    state = nm[host][protocol][port]['state'] 
                    name = nm[host][protocol][port]['name'] 
                    product = nm[host][protocol][port]['product'] 
                    self.results_area.append(f"Port: {port}, State: {state}, Service: {name}, Product: {product}")
        except Exception as e: 
             self.results_area.append(f"Error: {str(e)}")
                    
        # Here you can add code to map services to known vulnerabilities using a database like CVE 
    
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PortScannerApp()
    ex.show()
    sys.exit(app.exec_())
