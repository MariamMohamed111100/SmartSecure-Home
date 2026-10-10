"""Object, motion and fire/smoke detectors. Every detector returns a list of ``Detection``.

YOLO runs through OpenCV's DNN module on an ONNX export, so the image needs no PyTorch.
"""
from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path

import cv2
import numpy as np

from .types import Detection

log = logging.getLogger("vision.detect")

# COCO class id -> pipeline kind. COCO has no "package" class: backpack, handbag and suitcase are
# the closest stand-ins. Train/plug a real parcel model with PACKAGE_MODEL for production.
COCO_KINDS: dict[int, str] = {
    0: "person",
    2: "vehicle", 3: "vehicle", 5: "vehicle", 7: "vehicle",      # car, motorcycle, bus, truck
    24: "package", 26: "package", 28: "package",                 # backpack, handbag, suitcase
}


class YoloOnnx:
    """YOLOv8-style detector: ONNX output shape (1, 4 + classes, anchors)."""

    def __init__(self, model_path: Path, class_kinds: Mapping[int, str],
                 min_conf: float = 0.45, nms_iou: float = 0.5, size: int = 640,
                 kind_conf: Mapping[str, float] | None = None) -> None:
        self.net = cv2.dnn.readNetFromONNX(str(model_path))
        self.class_kinds = dict(class_kinds)
        self.min_conf, self.nms_iou, self.size = min_conf, nms_iou, size
        # per-kind confidence floor (a fire model needs a stricter one than a person model)
        self.class_conf = {c: (kind_conf or {}).get(k, min_conf)
                           for c, k in self.class_kinds.items()}

    def detect(self, frame: np.ndarray) -> list[Detection]:
        h, w = frame.shape[:2]
        scale = self.size / max(h, w)
        nw, nh = round(w * scale), round(h * scale)
        canvas = np.full((self.size, self.size, 3), 114, np.uint8)       # letterbox
        canvas[:nh, :nw] = cv2.resize(frame, (nw, nh))
        blob = cv2.dnn.blobFromImage(canvas, 1 / 255.0, (self.size, self.size), swapRB=True)
        self.net.setInput(blob)
        out = self.net.forward()[0].T                                     # (anchors, 4 + classes)
        scores = out[:, 4:]
        cls = scores.argmax(axis=1)
        conf = scores[np.arange(len(cls)), cls]
        floor = np.full(scores.shape[1], np.inf)           # classes we do not map never pass
        for c, t in self.class_conf.items():
            if c < len(floor):
                floor[c] = t
        keep = conf >= floor[cls]
        if not keep.any():
            return []
        out, cls, conf = out[keep], cls[keep], conf[keep]
        boxes = [[int((x - bw / 2) / scale), int((y - bh / 2) / scale),
                  int(bw / scale), int(bh / scale)] for x, y, bw, bh in out[:, :4]]
        idx = cv2.dnn.NMSBoxes(boxes, conf.tolist(), min(self.class_conf.values()), self.nms_iou)
        return [Detection(self.class_kinds[int(cls[i])], float(conf[i]), _clip(boxes[i], w, h))
                for i in np.array(idx).flatten()]


def _clip(b: list[int], w: int, h: int) -> tuple[int, int, int, int]:
    x, y = max(0, b[0]), max(0, b[1])
    return x, y, max(1, min(b[2], w - x)), max(1, min(b[3], h - y))


class MotionDetector:
    """Background subtraction: reports one detection when enough of the frame changed."""

    def __init__(self, min_area: float = 0.01, warmup_frames: int = 10) -> None:
        self.bg = cv2.createBackgroundSubtractorMOG2(history=200, varThreshold=32,
                                                     detectShadows=False)
        self.min_area, self.warmup = min_area, warmup_frames

    def detect(self, frame: np.ndarray) -> list[Detection]:
        small = cv2.GaussianBlur(cv2.resize(frame, (320, 180)), (5, 5), 0)
        mask = self.bg.apply(small)
        if self.warmup > 0:                       # let the background model settle first
            self.warmup -= 1
            return []
        mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, np.ones((3, 3), np.uint8))
        area = float(np.count_nonzero(mask)) / mask.size
        if area < self.min_area:
            return []
        return [Detection("motion", min(1.0, area * 10))]


class FireHeuristic:
    """Demo-grade flame detector: flame-coloured, bright pixels that also flicker between frames.

    Colour alone fires on orange sofas and sunsets, so a region must also change between frames.
    Off by default (FIRE_HEURISTIC=true to enable). Production should use a trained fire/smoke
    ONNX model through ``YoloOnnx`` instead.
    """

    def __init__(self, min_area: float = 0.005) -> None:
        self.prev: np.ndarray | None = None
        self.min_area = min_area

    def detect(self, frame: np.ndarray) -> list[Detection]:
        small = cv2.resize(frame, (320, 180))
        hsv = cv2.cvtColor(small, cv2.COLOR_BGR2HSV)
        flame = cv2.inRange(hsv, (0, 120, 200), (35, 255, 255))
        gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)
        moving = np.zeros_like(flame)
        if self.prev is not None:
            moving = cv2.threshold(cv2.absdiff(gray, self.prev), 25, 255, cv2.THRESH_BINARY)[1]
        self.prev = gray
        both = cv2.bitwise_and(flame, moving)
        area = float(np.count_nonzero(both)) / both.size
        if area < self.min_area:
            return []
        return [Detection("fire", min(0.6, 0.3 + area * 10))]      # capped: it is only a heuristic


def load_class_names(path: Path) -> list[str]:
    return [line.strip().lower() for line in path.read_text().splitlines() if line.strip()]


def fire_class_kinds(names: list[str]) -> dict[int, str]:
    """Map a custom fire/smoke model's class names (``<model>.names``) to pipeline kinds."""
    kinds: dict[int, str] = {}
    for i, name in enumerate(names):
        if "smoke" in name:
            kinds[i] = "smoke"
        elif "fire" in name or "flame" in name:
            kinds[i] = "fire"
    return kinds
