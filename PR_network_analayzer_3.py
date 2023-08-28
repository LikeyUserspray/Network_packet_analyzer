import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem, QPushButton, QVBoxLayout, QSplitter, QWidget, 
                             QFileDialog, QInputDialog, QMessageBox, QTextEdit, QDialog, QLineEdit, QHBoxLayout, QPushButton)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from scapy.all import *
from datetime import datetime
from time import time
import requests
import matplotlib.pyplot as plt

class CustomTreeWidgetItem(QTreeWidgetItem):
    def __lt__(self, otherItem):
        column = self.treeWidget().sortColumn()
        try:
            return float(self.text(column)) < float(otherItem.text(column))
        except ValueError:
            return self.text(column) < otherItem.text(column)
        
class PacketSnifferThread(QThread):
    new_packet_signal = pyqtSignal(object)

    def __init__(self, numpackets):
        super().__init__()
        self.num_packets = numpackets  # 사용되지 않는 변수를 실제로 사용하도록 변경
        self.running = True

    def run(self):
        try:
            def process_packet(x):
                if self.running:
                    self.new_packet_signal.emit(x)

            sniff(filter="ip", prn=process_packet, stop_filter=lambda x: not self.running)

        except Exception as e:
            print(f"An error occurred: {e}")

            sniff(filter="ip", prn=process_packet, stop_filter=lambda x: not self.running)

    def stop(self):
        self.running = False
        self.terminate()

    def emit_packet(self, packet):
        self.new_packet_signal.emit(packet)

class PacketAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Analyzer")
        self.setGeometry(100, 100, 2200, 1100)
        self.last_packet_time = 0 
        self.packet_count = 0 
        self.packets = []
        self.sniffer_thread = None
        self.toolbar = self.addToolBar("Control")

        self.tree = QTreeWidget(self)
        self.tree.setSortingEnabled(True)
        self.tree.setColumnCount(5)
        self.tree.setHeaderLabels(["No", "Time", "Source IP", "Destination IP", "Protocol"])
        self.tree.itemClicked.connect(self.show_packet_detail)

        self.detail_text_edit = QTextEdit(self)
        self.detail_text_edit.setReadOnly(True)

        self.raw_data_text_edit = QTextEdit(self)
        self.raw_data_text_edit.setReadOnly(True)
        fixed_font = QFont("Courier New", 10)
        self.raw_data_text_edit.setFont(fixed_font)

        btn_open_pcap = QPushButton("Analyze pcap file", self)
        btn_open_pcap.clicked.connect(self.load_pcap)

        btn_visualization = QPushButton("Visualization", self)  # btn_plot을 btn_visualization으로 이름 변경
        btn_visualization.clicked.connect(self.show_visualization_dialog)  # 새로운 메소드에 연결
        self.toolbar.addWidget(btn_visualization)


        btn_export = QPushButton("Export", self)
        btn_export.clicked.connect(self.export_packets)

        btn_run = QPushButton("Run", self)
        btn_run.clicked.connect(self.run_capture)
        self.toolbar.addWidget(btn_run)

        btn_pause = QPushButton("Pause", self)
        btn_pause.clicked.connect(self.pause_capture)
        self.toolbar.addWidget(btn_pause)

        # Search Bar 추가
        self.search_line_edit = QLineEdit(self)
        self.search_line_edit.setPlaceholderText("Search packets...")
        self.search_line_edit.returnPressed.connect(self.filter_packets)  # 엔터키를 누르면 filter_packets 호출

        self.search_button = QPushButton("Search", self)  # 검색 버튼
        self.search_button.clicked.connect(self.filter_packets)  # 버튼 클릭 시 filter_packets 호출

        btn_reset = QPushButton("Reset", self)  # Reset 버튼 추가
        btn_reset.clicked.connect(self.reset_capture)  # 버튼 클릭 시 reset_capture 호출
        self.toolbar.addWidget(btn_reset)  # 툴바에 버튼 추가


        search_layout = QHBoxLayout()
        search_layout.addWidget(self.search_line_edit)
        search_layout.addWidget(self.search_button)

        search_widget = QWidget()
        search_widget.setLayout(search_layout)
        self.toolbar.addWidget(search_widget)


        splitter = QSplitter(self)
        splitter.setOrientation(Qt.Orientation.Vertical)
        splitter.addWidget(self.tree)

        self.detail_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.detail_splitter.addWidget(self.detail_text_edit)
        self.detail_splitter.addWidget(self.raw_data_text_edit)

        splitter.addWidget(self.detail_splitter)
        layout = QVBoxLayout()
        layout.addWidget(splitter)
        layout.addWidget(btn_open_pcap)
        layout.addWidget(btn_export)

        central_widget = QWidget(self)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        splitter.setSizes([560, 240])
        self.detail_splitter.setSizes([400, 200])

    def filter_packets(self):
        search_term = self.search_line_edit.text().lower()
        self.tree.clear()

        for index, packet in enumerate(self.packets, start=1):
            timestamp = float(packet.time)
            dt = datetime.fromtimestamp(timestamp)
            readable_time = dt.strftime('%Y-%m-%d %H:%M:%S').lower()
            
            ip_layer = packet.getlayer(IP)
            protocol = "Unknown"

            if ip_layer:
                if packet.haslayer(TCP):
                    protocol = "TCP"
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
                if packet.haslayer(DNS):
                    protocol = "DNS"

                # 날짜 부분검색
                date_match = any(readable_time.startswith(st) for st in search_term.split())

                if (search_term in readable_time) or \
                   (search_term in ip_layer.src.lower()) or \
                   (search_term in ip_layer.dst.lower()) or \
                   (search_term in protocol.lower()):
                    item = QTreeWidgetItem([str(index), readable_time, ip_layer.src, ip_layer.dst, protocol])
                    self.tree.addTopLevelItem(item)

    def load_pcap(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select pcap file", "", "Pcap Files (*.pcap);;All Files (*)")
        if file_path:
            self.analyze_pcap(file_path)

    def capture_live(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()  # 기존 스레드가 실행 중이면 먼저 종료

        self.sniffer_thread = PacketSnifferThread(3)  # or another number
        self.sniffer_thread.new_packet_signal.connect(self.add_packet_to_treeview)
        self.sniffer_thread.start()

    def show_visualization_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Choose Visualization Type")
        layout = QVBoxLayout(dialog)

        btn_plot_port_counts = QPushButton("Plot Port Counts", dialog)
        btn_plot_port_counts.clicked.connect(lambda: self.plot_port_counts(close_dialog=dialog))
        
        btn_plot_protocol_counts = QPushButton("Protocol Counts", dialog)
        btn_plot_protocol_counts.clicked.connect(lambda: self.plot_protocol_counts(close_dialog=dialog))
        
        layout.addWidget(btn_plot_port_counts)
        layout.addWidget(btn_plot_protocol_counts)
        
        dialog.setLayout(layout)
        dialog.exec()

    def plot_protocol_counts(self, close_dialog=None):
        if not self.packets:
            msgbox = QMessageBox(self)
            msgbox.setWindowTitle("Plot Error")
            msgbox.setText("No packets to plot.")
            msgbox.exec()
            return
        
        protocols = ['TCP', 'UDP', 'ICMP', 'ARP']
        protocol_count = [0, 0, 0, 0]
        for packet in self.packets:
            if packet.haslayer(TCP):
                protocol_count[0] += 1
            if packet.haslayer(UDP):
                protocol_count[1] += 1
            if packet.haslayer(ICMP):
                protocol_count[2] += 1
            if packet.haslayer(ARP):
                protocol_count[3] += 1

        for i in range(0, 4):
            if protocol_count[i] == 0:
                protocols[i] = ''
        if close_dialog:
            close_dialog.accept()    
        plt.figure(figsize=(10, 6))
        plt.pie(protocol_count, labels=protocols, autopct= '%1.1f%%', startangle=90)
        plt.title("Protocol Communication Distribution")
        plt.show()
        
    def plot_port_counts(self, close_dialog=None):
        if close_dialog:
            close_dialog.accept()
        if not self.packets:
            msgbox = QMessageBox(self)
            msgbox.setWindowTitle("Plot Error")
            msgbox.setText("No packets to plot.")
            msgbox.exec()
            return

        port_count = {}
        for packet in self.packets:
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
                if port not in port_count:
                    port_count[port] = 1
                else:
                    port_count[port] += 1

        if port_count:
            # Sort by port count and take the top 5 ports
            sorted_port_count = sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:5]
            
            ports, counts = zip(*sorted_port_count)  # Unzip the tuples into two lists

            plt.bar([str(p) for p in ports], counts)  # Convert ports to strings for better x-axis formatting
            
            # Add counts above the bars
            for i, count in enumerate(counts):
                plt.text(i, count, str(count), ha='center', va='bottom')
            
            plt.xlabel('Port')
            plt.ylabel('Count')
            plt.title('Top 5 Port Counts')

            plt.show()
        else:
            msgbox = QMessageBox(self)
            msgbox.setWindowTitle("Plot Error")
            msgbox.setText("No TCP or UDP packets to plot.")
            msgbox.exec()

    def analyze_pcap(self, file_name):
        self.packets = rdpcap(file_name)
        ip_list = []  # IP 주소를 저장할 리스트

        for packet in self.packets:
            ip_layer = packet.getlayer(IP)
            if ip_layer:  # IP 레이어가 있는 경우
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                ip_list.append(src_ip)
                ip_list.append(dst_ip)

        unique_ip_list = list(set(ip_list))  # 중복 제거

        for ip in unique_ip_list:
            if check_malicious_ip(ip):  # 악성 IP 검사
                print(f"Malicious IP found: {ip}")  # 이 부분은 사용자에게 알릴 다른 방법으로 변경 가능

        self.update_packet_treeview()

    def add_packet_to_treeview(self, packet):
        self.packets.append(packet)

        current_time = time()
        elapsed_time = current_time - self.last_packet_time

        if elapsed_time >= 1.0:
            self.last_packet_time = current_time
            self.packet_count = 0

        if self.packet_count < 3:
            self.update_packet_treeview()
            self.packet_count += 1

    def update_packet_treeview(self):
        self.tree.clear()
        for index, packet in enumerate(self.packets, start=1):
            timestamp = float(packet.time)
            dt = datetime.fromtimestamp(timestamp)
            readable_time = dt.strftime('%Y-%m-%d %H:%M:%S')

            protocol = "Unknown"
            ip_layer = packet.getlayer(IP)
            if ip_layer:
                if packet.haslayer(TCP):
                    protocol = "TCP"
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"

            if ip_layer:
                item = CustomTreeWidgetItem([str(index), readable_time, ip_layer.src, ip_layer.dst, protocol])
            else:
                item = CustomTreeWidgetItem([str(index), readable_time, "-", "-", protocol])

            self.tree.addTopLevelItem(item)

    def show_packet_detail(self, item, column):
        index = int(item.text(0)) - 1
        selected_packet = self.packets[index]
        full_detail = selected_packet.show(dump=True)
        
        if selected_packet.haslayer(Raw):  # Raw 레이어의 존재를 확인
            raw_data = bytes(selected_packet[Raw])

            combined_lines = []
            for i in range(0, len(raw_data), 16):
                hex_chunk = raw_data[i:i+16]
                hex_part = " ".join(f"{byte:02x}" for byte in hex_chunk).ljust(48)
                ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in hex_chunk).ljust(16)
                combined_line = hex_part + "   " + ascii_part  # 합친 결과
                combined_lines.append(combined_line)
            
            self.raw_data_text_edit.setText("\n".join(combined_lines))

        else:
            self.raw_data_text_edit.clear()

        self.detail_text_edit.setText(full_detail)

    def show_custom_dialog(self, detail_text):
        dialog = QDialog(self)
        dialog.setWindowTitle("Packet Detail")
        layout = QVBoxLayout(dialog)
        
        text_edit = QTextEdit(dialog)
        text_edit.setText(detail_text)
        text_edit.setReadOnly(True)
        
        layout.addWidget(text_edit)
        dialog.setLayout(layout)
        dialog.resize(500, 400)  # Set to your preferred size
        dialog.exec()

    def pause_capture(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
            self.sniffer_thread = None

    def run_capture(self):
        self.sniffer_thread = PacketSnifferThread(3) 
        self.sniffer_thread.new_packet_signal.connect(self.add_packet_to_treeview)
        self.sniffer_thread.start()

    def reset_capture(self):
        self.packets.clear() 
        self.tree.clear()  
        self.detail_text_edit.clear()  
        self.raw_data_text_edit.clear()  

    def export_packets(self):
        if not self.packets:
            msgbox = QMessageBox(self)
            msgbox.setWindowTitle("Export Error")
            msgbox.setText("No packets to export.")
            msgbox.exec()
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Save Packets", "", "Text Files (*.txt)")
        if file_path:
            with open(file_path, 'w') as file:
                for index, packet in enumerate(self.packets, start=1):
                    timestamp = float(packet.time)
                    dt = datetime.fromtimestamp(timestamp)
                    readable_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                    file.write(f"No: {index}\n")
                    file.write(f"Captured Time: {readable_time}\n")
                    protocol = "Unknown"
                    if packet.haslayer(TCP):
                        protocol = "TCP"
                    elif packet.haslayer(DNS):
                        protocol = "DNS"
                    elif packet.haslayer(UDP):
                        protocol = "UDP"
                    elif packet.haslayer(ICMP):
                        protocol = "ICMP"
                    file.write(f"Protocol: {protocol}\n")
                    ip_layer = packet[IP]
                    file.write(f"Source IP: {ip_layer.src} -> Destination IP: {ip_layer.dst}\n")
                    file.write("\n")
            msgbox = QMessageBox(self)
            msgbox.setWindowTitle("Export Successful")
            msgbox.setText("Packets exported successfully!")
            msgbox.exec()


def check_malicious_ip(ip_address):
    url = f"https://urlhaus-api.abuse.ch/v1/host/{ip_address}/"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data['query_status'] == 'ok':
                return True  #악성 ip인 경우
    except Exception as e:
        print(f"An error occurred while checking IP: {e}")

    return False # 정상 ip인 경우



if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainWindow = PacketAnalyzer()
    mainWindow.show()
    sys.exit(app.exec())