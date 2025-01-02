import sys
from scapy.all import sniff, get_if_list
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QComboBox, QPushButton, QTextEdit
from PyQt5.QtCore import QThread, pyqtSignal

class CaptureThread(QThread):
    packet_captured = pyqtSignal(object)

    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.running = False

    def run(self):
        self.running = True
        sniff(iface=self.iface, prn=self.process_packet, stop_filter=self.should_stop)

    def process_packet(self, packet):
        if self.running:
            self.packet_captured.emit(packet)

    def should_stop(self, packet):
        return not self.running

    def stop(self):
        self.running = False

class ProtocolAnalyzerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.capture_thread = None

    def initUI(self):
        self.setWindowTitle('Analyse des Protocoles Réseau')
        self.setGeometry(100, 100, 800, 600)

        layout = QVBoxLayout()

        self.interface_label = QLabel('Sélectionnez une interface réseau :')
        layout.addWidget(self.interface_label)

        self.interface_dropdown = QComboBox()
        self.interface_dropdown.addItems(self.get_interfaces())
        layout.addWidget(self.interface_dropdown)

        self.capture_button = QPushButton('Capturer')
        self.capture_button.clicked.connect(self.start_capture)
        layout.addWidget(self.capture_button)

        self.stop_button = QPushButton('Arrêter')
        self.stop_button.clicked.connect(self.stop_capture)
        layout.addWidget(self.stop_button)

        self.status_label = QLabel('Statut de la Capture :')
        layout.addWidget(self.status_label)

        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        layout.addWidget(self.results_area)

        self.setLayout(layout)

    def get_interfaces(self):
        return get_if_list()

    def start_capture(self):
        self.results_area.clear()
        interface = self.interface_dropdown.currentText()
        self.results_area.append(f"Capturing packets on {interface}...")

        self.status_label.setText("Statut de la Capture : En cours")

        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            self.capture_thread.wait()

        self.capture_thread = CaptureThread(interface)
        self.capture_thread.packet_captured.connect(self.process_packet)
        self.capture_thread.start()

    def stop_capture(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.wait()
            self.results_area.append("Capture stopped.")
            self.status_label.setText("Statut de la Capture : Arrêtée")
            self.capture_thread = None

    def process_packet(self, packet):
        self.results_area.append(f"Packet: {packet.summary()}")
        if packet.haslayer('IP'):
            self.analyze_protocol(packet)

    def analyze_protocol(self, packet):
        if packet.haslayer('TCP') and packet.dport == 80:
            self.results_area.append("Insecure transmission detected: HTTP on port 80")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = ProtocolAnalyzerApp()
    ex.show()
    sys.exit(app.exec_())
