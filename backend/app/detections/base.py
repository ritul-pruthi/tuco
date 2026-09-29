import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from app.schemas.detection import Detection

logger = logging.getLogger(__name__)


@dataclass
class DetectionContext:
    investigation_id: str
    hosts: list[Any]
    flows: list[Any]
    dns_records: list[Any]
    http_records: list[Any]


class BaseDetector(ABC):
    rule_id: str
    title: str

    @abstractmethod
    def detect(self, context: DetectionContext) -> list[Detection]:
        raise NotImplementedError


class DetectionEngine:
    def __init__(self):
        self._detectors: list[BaseDetector] = []

    def register(self, detector: BaseDetector) -> None:
        self._detectors.append(detector)

    def run(self, context: DetectionContext) -> list[Detection]:
        detections: list[Detection] = []
        for detector in self._detectors:
            try:
                detections.extend(detector.detect(context))
            except Exception:
                logger.exception("Detector %s failed", detector.rule_id)
        return detections
