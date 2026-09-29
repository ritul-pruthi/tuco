from app.detections.base import DetectionEngine
from app.detections.beacon import BeaconDetector
from app.detections.dns_anomaly import DNSAnomalyDetector
from app.detections.http_indicator import HTTPIndicatorDetector
from app.detections.internal_recon import InternalReconDetector
from app.detections.large_transfer import LargeOutboundTransferDetector
from app.detections.port_scan import PortScanDetector


def build_default_engine() -> DetectionEngine:
    engine = DetectionEngine()
    engine.register(PortScanDetector())
    engine.register(InternalReconDetector())
    engine.register(BeaconDetector())
    engine.register(DNSAnomalyDetector())
    engine.register(HTTPIndicatorDetector())
    engine.register(LargeOutboundTransferDetector())
    return engine
