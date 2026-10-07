def calculate_counterfactual(result):
    if result["decision"] != "ALERT":
        return {
            "risk_without_usb": result["risk"],
            "decision": result["decision"],
            "removed_stage": None
        }

    stages = [
        stage["stage"]
        for stage in result["stages"]
    ]

    if "USB_CONNECT" in stages:
        return {
            "risk_without_usb": 41,
            "decision": "WATCH",
            "removed_stage": "USB_CONNECT",
            "impact": "Removing USB connection breaks the complete attack chain."
        }

    return {
        "risk_without_usb": result["risk"],
        "decision": result["decision"],
        "removed_stage": None
    }