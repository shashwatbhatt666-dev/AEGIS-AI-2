# ==========================================================
# AEGIS AI - RULE-BASED THREAT DETECTION ENGINE
# ==========================================================
#
# Purpose:
# Analyze a single security event using explainable
# defensive detection rules.
#
# Output:
# - Triggered rules
# - Evidence
# - Rule score
# - Severity
# - Threat status
#
# ==========================================================


from typing import Dict, Any, List


# ==========================================================
# SEVERITY CALCULATION
# ==========================================================

def calculate_severity(score: int) -> str:
    """
    Convert a numerical risk score into a severity level.
    """

    if score >= 80:
        return "Critical"

    elif score >= 60:
        return "High"

    elif score >= 35:
        return "Medium"

    elif score >= 15:
        return "Low"

    return "Informational"


# ==========================================================
# HELPER FUNCTION - ADD DETECTION RULE
# ==========================================================

def add_rule(
    triggered_rules: List[Dict[str, Any]],
    rule_id: str,
    rule_name: str,
    description: str,
    score: int,
    evidence: str
):
    """
    Add a triggered detection rule to the results.
    """

    triggered_rules.append(
        {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "description": description,
            "score": score,
            "evidence": evidence
        }
    )


# ==========================================================
# MAIN RULE ENGINE
# ==========================================================

def analyze_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze one security event and return
    explainable rule-based detection results.
    """

    triggered_rules = []

    # ------------------------------------------------------
    # Read event values safely
    # ------------------------------------------------------

    event_id = str(
        event.get(
            "event_id",
            "UNKNOWN"
        )
    )

    event_type = str(
        event.get(
            "event_type",
            "unknown"
        )
    ).lower()

    failed_attempts = int(
        event.get(
            "failed_attempts",
            0
        )
    )

    request_count = int(
        event.get(
            "request_count",
            0
        )
    )

    bytes_transferred = int(
        event.get(
            "bytes_transferred",
            0
        )
    )

    login_hour = int(
        event.get(
            "login_hour",
            12
        )
    )

    new_device = int(
        event.get(
            "new_device",
            0
        )
    )

    privilege_change = int(
        event.get(
            "privilege_change",
            0
        )
    )

    sensitive_resource = int(
        event.get(
            "sensitive_resource",
            0
        )
    )

    asset_criticality = str(
        event.get(
            "asset_criticality",
            "Low"
        )
    ).lower()


    # ======================================================
    # RULE 001 - EXCESSIVE FAILED AUTHENTICATION
    # ======================================================

    if failed_attempts >= 20:

        add_rule(
            triggered_rules,
            "AEG-R001",
            "Excessive Authentication Failures",
            "A very high number of failed authentication "
            "attempts was detected.",
            35,
            f"{failed_attempts} failed attempts"
        )

    elif failed_attempts >= 10:

        add_rule(
            triggered_rules,
            "AEG-R001",
            "Repeated Authentication Failures",
            "Multiple failed authentication attempts "
            "were detected.",
            25,
            f"{failed_attempts} failed attempts"
        )

    elif failed_attempts >= 5:

        add_rule(
            triggered_rules,
            "AEG-R001",
            "Elevated Authentication Failures",
            "An unusual number of authentication "
            "failures was detected.",
            15,
            f"{failed_attempts} failed attempts"
        )


    # ======================================================
    # RULE 002 - OFF-HOURS ACTIVITY
    # ======================================================

    if login_hour < 6 or login_hour >= 22:

        add_rule(
            triggered_rules,
            "AEG-R002",
            "Off-Hours Activity",
            "Activity occurred outside the expected "
            "business-hour window.",
            15,
            f"Activity detected at hour {login_hour}:00"
        )


    # ======================================================
    # RULE 003 - NEW OR UNKNOWN DEVICE
    # ======================================================

    if new_device == 1:

        add_rule(
            triggered_rules,
            "AEG-R003",
            "New Device Detected",
            "The user accessed the environment from "
            "an unfamiliar device.",
            15,
            "new_device = 1"
        )


    # ======================================================
    # RULE 004 - PRIVILEGE CHANGE
    # ======================================================

    if privilege_change == 1:

        add_rule(
            triggered_rules,
            "AEG-R004",
            "Privilege Change Detected",
            "A privilege or administrative permission "
            "change was observed.",
            30,
            "privilege_change = 1"
        )


    # ======================================================
    # RULE 005 - SENSITIVE RESOURCE ACCESS
    # ======================================================

    if sensitive_resource == 1:

        add_rule(
            triggered_rules,
            "AEG-R005",
            "Sensitive Resource Access",
            "The event involved access to a sensitive "
            "resource.",
            20,
            "sensitive_resource = 1"
        )


    # ======================================================
    # RULE 006 - ABNORMALLY HIGH REQUEST VOLUME
    # ======================================================

    if request_count >= 2000:

        add_rule(
            triggered_rules,
            "AEG-R006",
            "Extreme Request Volume",
            "An extremely high number of requests "
            "was detected.",
            35,
            f"{request_count} requests"
        )

    elif request_count >= 700:

        add_rule(
            triggered_rules,
            "AEG-R006",
            "High Request Volume",
            "The event generated an unusually high "
            "number of requests.",
            25,
            f"{request_count} requests"
        )


    # ======================================================
    # RULE 007 - LARGE DATA TRANSFER
    # ======================================================

    if bytes_transferred >= 100_000_000:

        add_rule(
            triggered_rules,
            "AEG-R007",
            "Extreme Data Transfer",
            "An extremely large volume of data was "
            "transferred.",
            40,
            f"{bytes_transferred:,} bytes transferred"
        )

    elif bytes_transferred >= 10_000_000:

        add_rule(
            triggered_rules,
            "AEG-R007",
            "Large Data Transfer",
            "A large volume of data was transferred.",
            30,
            f"{bytes_transferred:,} bytes transferred"
        )

    elif bytes_transferred >= 1_000_000:

        add_rule(
            triggered_rules,
            "AEG-R007",
            "Elevated Data Transfer",
            "Data transfer volume exceeded the normal "
            "baseline.",
            15,
            f"{bytes_transferred:,} bytes transferred"
        )


    # ======================================================
    # RULE 008 - CRITICAL ASSET INVOLVEMENT
    # ======================================================

    if asset_criticality == "critical":

        add_rule(
            triggered_rules,
            "AEG-R008",
            "Critical Asset Involved",
            "The security event affected a critical asset.",
            25,
            "asset_criticality = Critical"
        )

    elif asset_criticality == "high":

        add_rule(
            triggered_rules,
            "AEG-R008",
            "High-Value Asset Involved",
            "The security event affected a high-value asset.",
            15,
            "asset_criticality = High"
        )


    # ======================================================
    # RULE 009 - SUSPICIOUS EVENT TYPE
    # ======================================================

    suspicious_event_types = {

        "repeated_login_failure":
            20,

        "restricted_resource_access":
            20,

        "unusual_resource_access":
            15,

        "privilege_change":
            25,

        "admin_permission_request":
            20,

        "high_request_rate":
            20,

        "unusual_network_connection":
            15,

        "large_data_transfer":
            25,

        "sensitive_data_access":
            25
    }


    if event_type in suspicious_event_types:

        event_type_score = (
            suspicious_event_types[
                event_type
            ]
        )

        add_rule(
            triggered_rules,
            "AEG-R009",
            "Suspicious Event Pattern",
            "The event type matches a known suspicious "
            "behavior pattern.",
            event_type_score,
            f"event_type = {event_type}"
        )


    # ======================================================
    # CALCULATE FINAL RULE SCORE
    # ======================================================

    raw_score = sum(
        rule["score"]
        for rule in triggered_rules
    )

    # Keep score between 0 and 100
    rule_score = min(
        raw_score,
        100
    )


    # ======================================================
    # DETERMINE SEVERITY
    # ======================================================

    severity = calculate_severity(
        rule_score
    )


    # ======================================================
    # DETERMINE THREAT STATUS
    # ======================================================

    is_suspicious = (
        rule_score >= 35
    )

    should_create_incident = (
        rule_score >= 60
    )


    # ======================================================
    # RETURN ANALYSIS RESULT
    # ======================================================

    return {

        "event_id":
            event_id,

        "event_type":
            event_type,

        "rule_score":
            rule_score,

        "raw_score":
            raw_score,

        "severity":
            severity,

        "is_suspicious":
            is_suspicious,

        "should_create_incident":
            should_create_incident,

        "rules_triggered":
            len(
                triggered_rules
            ),

        "triggered_rules":
            triggered_rules
    }


# ==========================================================
# TEST THE RULE ENGINE
# ==========================================================

if __name__ == "__main__":

    test_event = {

        "event_id":
            "EVT-TEST-001",

        "event_type":
            "repeated_login_failure",

        "failed_attempts":
            27,

        "request_count":
            850,

        "bytes_transferred":
            45000,

        "login_hour":
            3,

        "new_device":
            1,

        "privilege_change":
            0,

        "sensitive_resource":
            1,

        "asset_criticality":
            "Critical"
    }


    result = analyze_event(
        test_event
    )


    print(
        "\n"
        "=========================================="
    )

    print(
        " AEGIS AI - RULE ENGINE TEST"
    )

    print(
        "=========================================="
    )


    print(
        f"\nEvent ID: "
        f"{result['event_id']}"
    )

    print(
        f"Event Type: "
        f"{result['event_type']}"
    )

    print(
        f"\nRule Score: "
        f"{result['rule_score']}/100"
    )

    print(
        f"Severity: "
        f"{result['severity']}"
    )

    print(
        f"Suspicious: "
        f"{result['is_suspicious']}"
    )

    print(
        f"Create Incident: "
        f"{result['should_create_incident']}"
    )


    print(
        "\nTRIGGERED RULES"
    )

    print(
        "------------------------------------------"
    )


    for rule in result[
        "triggered_rules"
    ]:

        print(
            f"\n[{rule['rule_id']}] "
            f"{rule['rule_name']}"
        )

        print(
            f"Evidence: "
            f"{rule['evidence']}"
        )

        print(
            f"Score: "
            f"+{rule['score']}"
        )


    print(
        "\n"
        "==========================================\n"
    )