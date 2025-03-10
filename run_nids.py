run_nids.py
v2
from nids.packet_sniffer import start_sniffing
from nids.protocol_analyzer import analyze_packet
from nids.signature_based_detection import detect_signatures
from nids.anomaly_based_detection import AnomalyDetector
from nids.logger import log_event
