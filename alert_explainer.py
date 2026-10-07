def explain_alert(result):
    if result["decision"] != "ALERT":
        return {
            "why": [
                "No complete attack chain was detected."
            ]
        }

    user = result.get(
        "user",
        "unknown"
    )

    stages = [
        stage["stage"]
        for stage in result["stages"]
    ]

    return {
        "why": [
            f"User {user} triggered the detected attack sequence.",
            f"Attack chain: {result['attack_dna']}.",
            f"All {len(stages)} required stages have supporting event IDs.",
            "The stages occurred in chronological order.",
            "Privilege escalation followed by file access, USB connection, and file copy indicates possible data exfiltration.",
            f"Detection risk score: {result['risk']}/100."
        ]
    }