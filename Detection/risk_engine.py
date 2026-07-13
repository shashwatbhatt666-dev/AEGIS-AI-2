# ==========================================================
# AEGIS AI - DYNAMIC RISK SCORING ENGINE
# ==========================================================
#
# Purpose:
# Combine multiple security signals into one explainable
# final risk score.
#
# Inputs:
# - Rule Engine result
# - ML Anomaly result
# - Asset criticality
# - Sensitive resource involvement
# - Privilege changes
# - Detection agreement
#
# Output:
# - Final risk score
# - Severity
# - Confidence
# - Priority
# - Incident decision
# - Explainable score breakdown
#
# ==========================================================


from pathlib import Path
from typing import Dict, Any
import sys


# ==========================================================
# PROJECT PATH SETUP
# ==========================================================
#
# This allows this file to import:
#
# Detection/rule_engine.py
# ML/anomaly_detector.py
#
# when running:
#
# python Detection/risk_engine.py
#
# ==========================================================

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = CURRENT_DIR.parent

if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_DIR)
    )


# ==========================================================
# IMPORT AEGIS INTELLIGENCE ENGINES
# ==========================================================

from Detection.rule_engine import analyze_event
from ML.anomaly_detector import analyze_anomaly


# ==========================================================
# ASSET CRITICALITY WEIGHTS
# ==========================================================

ASSET_CRITICALITY_WEIGHTS = {

    "low": 0,

    "medium": 3,

    "high": 7,

    "critical": 10

}


# ==========================================================
# SEVERITY CALCULATION
# ==========================================================

def calculate_risk_severity(
    risk_score: int
) -> str:

    """
    Convert final risk score into severity.
    """

    if risk_score >= 85:
        return "Critical"

    elif risk_score >= 65:
        return "High"

    elif risk_score >= 40:
        return "Medium"

    elif risk_score >= 20:
        return "Low"

    return "Informational"


# ==========================================================
# INCIDENT PRIORITY
# ==========================================================

def calculate_priority(
    risk_score: int
) -> str:

    """
    Assign operational incident priority.
    """

    if risk_score >= 85:
        return "P1"

    elif risk_score >= 65:
        return "P2"

    elif risk_score >= 40:
        return "P3"

    elif risk_score >= 20:
        return "P4"

    return "P5"


# ==========================================================
# CONFIDENCE CALCULATION
# ==========================================================

def calculate_confidence(
    rule_score: int,
    anomaly_score: int,
    is_anomaly: bool,
    rules_triggered: int
) -> Dict[str, Any]:

    """
    Calculate confidence based on agreement between
    independent detection systems.
    """

    confidence_score = 30

    confidence_reasons = []


    # ------------------------------------------------------
    # Strong Rule Engine evidence
    # ------------------------------------------------------

    if rule_score >= 80:

        confidence_score += 25

        confidence_reasons.append(
            "Strong rule-based detection evidence"
        )

    elif rule_score >= 60:

        confidence_score += 20

        confidence_reasons.append(
            "Significant rule-based detection evidence"
        )

    elif rule_score >= 35:

        confidence_score += 10

        confidence_reasons.append(
            "Moderate rule-based detection evidence"
        )


    # ------------------------------------------------------
    # ML anomaly evidence
    # ------------------------------------------------------

    if is_anomaly:

        confidence_score += 20

        confidence_reasons.append(
            "ML model identified anomalous behavior"
        )


    if anomaly_score >= 85:

        confidence_score += 15

        confidence_reasons.append(
            "Very high behavioral anomaly score"
        )

    elif anomaly_score >= 70:

        confidence_score += 10

        confidence_reasons.append(
            "High behavioral anomaly score"
        )


    # ------------------------------------------------------
    # Multiple independent rules
    # ------------------------------------------------------

    if rules_triggered >= 5:

        confidence_score += 10

        confidence_reasons.append(
            "Multiple independent detection rules triggered"
        )

    elif rules_triggered >= 3:

        confidence_score += 5

        confidence_reasons.append(
            "Several detection rules triggered"
        )


    # ------------------------------------------------------
    # Detection agreement bonus
    # ------------------------------------------------------

    rule_detected_threat = (
        rule_score >= 35
    )

    if rule_detected_threat and is_anomaly:

        confidence_score += 10

        confidence_reasons.append(
            "Rule Engine and ML Anomaly Engine agree"
        )


    confidence_score = min(
        confidence_score,
        100
    )


    if confidence_score >= 90:

        confidence_level = "Very High"

    elif confidence_score >= 75:

        confidence_level = "High"

    elif confidence_score >= 55:

        confidence_level = "Medium"

    else:

        confidence_level = "Low"


    return {

        "score":
            confidence_score,

        "level":
            confidence_level,

        "reasons":
            confidence_reasons

    }


# ==========================================================
# MAIN DYNAMIC RISK ENGINE
# ==========================================================

def calculate_risk(
    event: Dict[str, Any],
    rule_result: Dict[str, Any] = None,
    anomaly_result: Dict[str, Any] = None
) -> Dict[str, Any]:

    """
    Calculate the final AEGIS AI risk score.

    If Rule Engine and Anomaly Engine results are not
    supplied, this function automatically runs them.
    """


    # ------------------------------------------------------
    # Run Rule Engine if needed
    # ------------------------------------------------------

    if rule_result is None:

        rule_result = analyze_event(
            event
        )


    # ------------------------------------------------------
    # Run Anomaly Engine if needed
    # ------------------------------------------------------

    if anomaly_result is None:

        anomaly_result = analyze_anomaly(
            event
        )


    # ------------------------------------------------------
    # Read intelligence scores
    # ------------------------------------------------------

    rule_score = int(
        rule_result.get(
            "rule_score",
            0
        )
    )

    anomaly_score = int(
        anomaly_result.get(
            "anomaly_score",
            0
        )
    )

    is_anomaly = bool(
        anomaly_result.get(
            "is_anomaly",
            False
        )
    )

    rules_triggered = int(
        rule_result.get(
            "rules_triggered",
            0
        )
    )


    # ======================================================
    # CORE WEIGHTED RISK SCORE
    # ======================================================
    #
    # Rule Engine:       Maximum 45 points
    # Anomaly Engine:    Maximum 35 points
    # Context:           Maximum 20+ points
    #
    # Final score is capped at 100.
    #
    # ======================================================

    rule_component = round(
        rule_score * 0.45
    )

    anomaly_component = round(
        anomaly_score * 0.35
    )


    # ======================================================
    # CONTEXTUAL RISK
    # ======================================================

    context_score = 0

    context_factors = []


    # ------------------------------------------------------
    # Asset criticality
    # ------------------------------------------------------

    asset_criticality = str(
        event.get(
            "asset_criticality",
            "Low"
        )
    ).strip().lower()


    asset_score = (
        ASSET_CRITICALITY_WEIGHTS.get(
            asset_criticality,
            0
        )
    )


    if asset_score > 0:

        context_score += asset_score

        context_factors.append(

            {
                "factor":
                    "Asset Criticality",

                "score":
                    asset_score,

                "evidence":
                    asset_criticality.title()
            }

        )


    # ------------------------------------------------------
    # Sensitive resource
    # ------------------------------------------------------

    sensitive_resource = int(
        event.get(
            "sensitive_resource",
            0
        )
    )


    if sensitive_resource == 1:

        context_score += 5

        context_factors.append(

            {
                "factor":
                    "Sensitive Resource",

                "score":
                    5,

                "evidence":
                    "Sensitive resource involved"
            }

        )


    # ------------------------------------------------------
    # Privilege change
    # ------------------------------------------------------

    privilege_change = int(
        event.get(
            "privilege_change",
            0
        )
    )


    if privilege_change == 1:

        context_score += 5

        context_factors.append(

            {
                "factor":
                    "Privilege Change",

                "score":
                    5,

                "evidence":
                    "Privilege modification detected"
            }

        )


    # ======================================================
    # DETECTION AGREEMENT BONUS
    # ======================================================

    agreement_bonus = 0

    rule_detected_threat = (
        rule_score >= 35
    )


    if rule_detected_threat and is_anomaly:

        agreement_bonus = 5

        context_factors.append(

            {
                "factor":
                    "Detection Agreement",

                "score":
                    5,

                "evidence":
                    "Rule Engine and ML Anomaly Engine agree"
            }

        )


    # ======================================================
    # FINAL RISK SCORE
    # ======================================================

    raw_final_score = (

        rule_component

        +

        anomaly_component

        +

        context_score

        +

        agreement_bonus

    )


    final_risk_score = min(
        round(
            raw_final_score
        ),
        100
    )


    # ======================================================
    # SEVERITY
    # ======================================================

    severity = calculate_risk_severity(
        final_risk_score
    )


    # ======================================================
    # PRIORITY
    # ======================================================

    priority = calculate_priority(
        final_risk_score
    )


    # ======================================================
    # CONFIDENCE
    # ======================================================

    confidence = calculate_confidence(

        rule_score=
            rule_score,

        anomaly_score=
            anomaly_score,

        is_anomaly=
            is_anomaly,

        rules_triggered=
            rules_triggered

    )


    # ======================================================
    # INCIDENT DECISION
    # ======================================================

    should_create_incident = (

        final_risk_score >= 65

        or

        (
            is_anomaly
            and
            rule_score >= 60
        )

    )


    # ======================================================
    # RECOMMENDED RESPONSE LEVEL
    # ======================================================

    if final_risk_score >= 85:

        recommended_response = (
            "Immediate investigation and containment review"
        )

    elif final_risk_score >= 65:

        recommended_response = (
            "High-priority analyst investigation"
        )

    elif final_risk_score >= 40:

        recommended_response = (
            "Review event and monitor related activity"
        )

    elif final_risk_score >= 20:

        recommended_response = (
            "Continue monitoring"
        )

    else:

        recommended_response = (
            "No immediate action required"
        )


    # ======================================================
    # RETURN FINAL RISK ANALYSIS
    # ======================================================

    return {

        "event_id":
            str(
                event.get(
                    "event_id",
                    "UNKNOWN"
                )
            ),

        "final_risk_score":
            final_risk_score,

        "severity":
            severity,

        "priority":
            priority,

        "should_create_incident":
            should_create_incident,

        "recommended_response":
            recommended_response,


        # --------------------------------------------------
        # Confidence
        # --------------------------------------------------

        "confidence":

            confidence,


        # --------------------------------------------------
        # Score breakdown
        # --------------------------------------------------

        "score_breakdown":

            {

                "rule_engine":

                    {

                        "original_score":
                            rule_score,

                        "weight":
                            "45%",

                        "contribution":
                            rule_component

                    },


                "anomaly_engine":

                    {

                        "original_score":
                            anomaly_score,

                        "weight":
                            "35%",

                        "contribution":
                            anomaly_component

                    },


                "context":

                    {

                        "contribution":
                            context_score,

                        "factors":
                            context_factors

                    },


                "detection_agreement_bonus":
                    agreement_bonus

            },


        # --------------------------------------------------
        # Original intelligence results
        # --------------------------------------------------

        "rule_analysis":
            rule_result,

        "anomaly_analysis":
            anomaly_result

    }


# ==========================================================
# DISPLAY RISK REPORT
# ==========================================================

def display_risk_report(
    result: Dict[str, Any]
):

    """
    Print a readable AEGIS AI risk report.
    """


    print(
        "\n"
        "=================================================="
    )

    print(
        " AEGIS AI - DYNAMIC RISK ANALYSIS"
    )

    print(
        "=================================================="
    )


    print(
        f"\nEvent ID: "
        f"{result['event_id']}"
    )


    print(
        "\nFINAL ASSESSMENT"
    )

    print(
        "--------------------------------------------------"
    )


    print(
        f"Risk Score:        "
        f"{result['final_risk_score']}/100"
    )

    print(
        f"Severity:          "
        f"{result['severity']}"
    )

    print(
        f"Priority:          "
        f"{result['priority']}"
    )

    print(
        f"Confidence:        "
        f"{result['confidence']['level']} "
        f"({result['confidence']['score']}%)"
    )

    print(
        f"Create Incident:   "
        f"{result['should_create_incident']}"
    )

    print(
        f"Response:          "
        f"{result['recommended_response']}"
    )


    print(
        "\nSCORE BREAKDOWN"
    )

    print(
        "--------------------------------------------------"
    )


    rule_breakdown = (
        result[
            "score_breakdown"
        ][
            "rule_engine"
        ]
    )


    anomaly_breakdown = (
        result[
            "score_breakdown"
        ][
            "anomaly_engine"
        ]
    )


    print(

        f"Rule Engine:       "
        f"{rule_breakdown['original_score']}/100 "
        f"→ +{rule_breakdown['contribution']}"

    )


    print(

        f"Anomaly Engine:    "
        f"{anomaly_breakdown['original_score']}/100 "
        f"→ +{anomaly_breakdown['contribution']}"

    )


    print(

        f"Context:           "
        f"+{result['score_breakdown']['context']['contribution']}"

    )


    print(

        f"Agreement Bonus:   "
        f"+{result['score_breakdown']['detection_agreement_bonus']}"

    )


    print(
        "\nCONTEXTUAL RISK FACTORS"
    )

    print(
        "--------------------------------------------------"
    )


    context_factors = (

        result[
            "score_breakdown"
        ][
            "context"
        ][
            "factors"
        ]

    )


    if context_factors:

        for factor in context_factors:

            print(

                f"• {factor['factor']}: "
                f"+{factor['score']}"

            )

            print(

                f"  Evidence: "
                f"{factor['evidence']}"

            )

    else:

        print(
            "No additional contextual risk factors."
        )


    print(
        "\nCONFIDENCE REASONS"
    )

    print(
        "--------------------------------------------------"
    )


    confidence_reasons = (

        result[
            "confidence"
        ][
            "reasons"
        ]

    )


    if confidence_reasons:

        for reason in confidence_reasons:

            print(
                f"• {reason}"
            )

    else:

        print(
            "Limited independent detection evidence."
        )


    print(
        "\n"
        "==================================================\n"
    )


# ==========================================================
# TEST THE COMPLETE RISK ENGINE
# ==========================================================

if __name__ == "__main__":


    # ------------------------------------------------------
    # TEST 1 - NORMAL EVENT
    # ------------------------------------------------------

    normal_event = {

        "event_id":
            "EVT-RISK-NORMAL-001",

        "event_type":
            "successful_login",

        "source_ip":
            "192.168.1.25",

        "destination_ip":
            "192.168.1.10",

        "user_id":
            "employee_12",

        "device_id":
            "WORKSTATION-12",

        "protocol":
            "HTTPS",

        "failed_attempts":
            0,

        "request_count":
            42,

        "bytes_transferred":
            15000,

        "login_hour":
            11,

        "new_device":
            0,

        "privilege_change":
            0,

        "sensitive_resource":
            0,

        "asset_criticality":
            "Medium"

    }


    # ------------------------------------------------------
    # TEST 2 - CRITICAL EVENT
    # ------------------------------------------------------

    critical_event = {

        "event_id":
            "EVT-RISK-CRITICAL-001",

        "event_type":
            "repeated_login_failure",

        "source_ip":
            "203.0.113.45",

        "destination_ip":
            "192.168.1.10",

        "user_id":
            "employee_17",

        "device_id":
            "UNKNOWN-DEVICE",

        "protocol":
            "HTTPS",

        "failed_attempts":
            38,

        "request_count":
            3200,

        "bytes_transferred":
            180000000,

        "login_hour":
            3,

        "new_device":
            1,

        "privilege_change":
            1,

        "sensitive_resource":
            1,

        "asset_criticality":
            "Critical"

    }


    print(
        "\n\nTEST 1: NORMAL SECURITY EVENT"
    )

    normal_result = calculate_risk(
        normal_event
    )

    display_risk_report(
        normal_result
    )


    print(
        "\n\nTEST 2: CRITICAL SECURITY EVENT"
    )

    critical_result = calculate_risk(
        critical_event
    )

    display_risk_report(
        critical_result
    )