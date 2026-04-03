def calculate_risk_score(abuse_score: int, vt_malicious: int, otx_pulses: int) -> int:
    raw_score = (abuse_score * 0.4) + (vt_malicious * 2) + (otx_pulses * 3)
    return int(max(0, min(100, round(raw_score))))


def get_risk_level(score: int) -> str:
    if score <= 30:
        return "LOW"
    if score <= 70:
        return "MEDIUM"
    return "HIGH"
