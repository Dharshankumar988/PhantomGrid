def extract_threat_categories(abuse_data: dict, vt_data: dict, otx_data: dict) -> list[str]:
    text_blobs: list[str] = []

    abuse_labels = [
        str(abuse_data.get("usageType", "")),
        str(abuse_data.get("domain", "")),
        str(abuse_data.get("countryCode", "")),
    ]
    text_blobs.extend(abuse_labels)

    vt_tags = vt_data.get("tags", []) if isinstance(vt_data.get("tags", []), list) else []
    text_blobs.extend([str(tag) for tag in vt_tags])

    pulses = otx_data.get("pulse_info", {}).get("pulses", [])
    for pulse in pulses:
        text_blobs.append(str(pulse.get("name", "")))
        tags = pulse.get("tags", [])
        if isinstance(tags, list):
            text_blobs.extend([str(tag) for tag in tags])

    combined = " ".join(text_blobs).lower()

    categories = set()
    if any(keyword in combined for keyword in ["spam", "spammer"]):
        categories.add("Spam")
    if any(keyword in combined for keyword in ["botnet", "bot", "c2"]):
        categories.add("Botnet")
    if any(keyword in combined for keyword in ["malware", "trojan", "ransomware", "worm"]):
        categories.add("Malware")
    if any(keyword in combined for keyword in ["phish", "credential theft", "spoof"]):
        categories.add("Phishing")

    return sorted(categories)
