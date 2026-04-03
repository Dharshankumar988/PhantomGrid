def calculate_confidence_score(report_count: int, detection_count: int, pulse_count: int) -> int:
    raw_confidence = (report_count * 0.8) + (detection_count * 2.5) + (pulse_count * 4)
    return int(max(0, min(100, round(raw_confidence))))
