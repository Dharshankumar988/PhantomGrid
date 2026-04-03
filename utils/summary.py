def generate_summary(data: dict) -> str:
    categories = data.get("threat_categories") or []
    category_text = ", ".join(categories) if categories else "no dominant threat categories"

    return (
        f"{data['target']} is {data['risk_level']} risk due to {category_text}, "
        f"detected by {data['detection']['malicious']} engines."
    )
