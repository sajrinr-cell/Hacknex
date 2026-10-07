from dataclasses import dataclass


@dataclass
class Event:
    event_id: str
    source: str
    raw_timestamp: str
    corrected_timestamp: str
    user: str
    device: str
    ip: str
    action: str
    object: str
    confidence: float