from app.detections.base import DetectionEngine
from app.detections.port_scan import PortScanDetector


def build_default_engine() -> DetectionEngine:
    engine = DetectionEngine()
    engine.register(PortScanDetector())
    return engine
