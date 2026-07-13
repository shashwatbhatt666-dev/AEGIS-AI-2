# ==========================================================
# AEGIS AI - EVENT CORRELATION ENGINE
# ==========================================================
#
# Purpose:
# Correlate multiple related security events into meaningful
# incidents and attack stories.
#
# Correlation considers:
# - Same user
# - Same source IP
# - Same device
# - Time proximity
# - Event sequence
# - Individual event risk
#
# ==========================================================


from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime, timedelta
import sys
import uuid


# ==========================================================
# PROJECT PATH SETUP
# ==========================================================

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = CURRENT_DIR.parent

if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_DIR)
    )


# ==========================================================
# IMPORT RISK ENGINE
# ==========================================================

from Detection.risk_engine import calculate_risk


# ==========================================================
# CORRELATION CONFIGURATION
# ==========================================================

CORRELATION_WINDOW_MINUTES = 60


# ==========================================================
# EVENT TYPE GROUPS
# ==========================================================

AUTHENTICATION_EVENTS = {

    "repeated_login_failure",
    "unusual_login",
    "new_device_login",
    "off_hours_login",
    "successful_login"

}


PRIVILEGE_EVENTS = {

    "privilege_change",
    "admin_permission_request"

}


ACCESS_EVENTS = {

    "restricted_resource_access",
    "unusual_resource_access",
    "sensitive_data_access"

}


NETWORK_EVENTS = {

    "high_request_rate",
    "unusual_network_connection"

}


DATA_TRANSFER_EVENTS = {

    "large_data_transfer",
    "sensitive_data_access"

}


# ==========================================================
# ATTACK STORY PATTERNS
# ==========================================================

ATTACK_PATTERNS = {

    "Potential Account Compromise": {

        "required_groups": [
            "authentication",
            "access"
        ],

        "base_score": 15

    },


    "Privilege Escalation Chain": {

        "required_groups": [
            "authentication",
            "privilege"
        ],

        "base_score": 20

    },


    "Sensitive Resource Compromise": {

        "required_groups": [
            "privilege",
            "access"
        ],

        "base_score": 20

    },


    "Potential Data Exfiltration": {

        "required_groups": [
            "access",
            "data_transfer"
        ],

        "base_score": 25

    },


    "Multi-Stage Security Incident": {

        "required_groups": [
            "authentication",
            "privilege",
            "access"
        ],

        "base_score": 30

    }

}


# ==========================================================
# PARSE TIMESTAMP
# ==========================================================

def parse_timestamp(
    timestamp: Any
) -> datetime:

    """
    Convert timestamp into a datetime object.
    """

    if isinstance(
        timestamp,
        datetime
    ):
        return timestamp


    timestamp = str(
        timestamp
    )


    supported_formats = [

        "%Y-%m-%d %H:%M:%S",

        "%Y-%m-%dT%H:%M:%S"

    ]


    for timestamp_format in supported_formats:

        try:

            return datetime.strptime(
                timestamp,
                timestamp_format
            )

        except ValueError:

            continue


    raise ValueError(

        f"Unsupported timestamp format: "
        f"{timestamp}"

    )


# ==========================================================
# GET EVENT GROUPS
# ==========================================================

def get_event_groups(
    event: Dict[str, Any]
) -> List[str]:

    """
    Convert an event type into one or more behavioral groups.
    """

    groups = []

    event_type = str(

        event.get(
            "event_type",
            ""
        )

    ).lower()


    if event_type in AUTHENTICATION_EVENTS:

        groups.append(
            "authentication"
        )


    if event_type in PRIVILEGE_EVENTS:

        groups.append(
            "privilege"
        )


    if event_type in ACCESS_EVENTS:

        groups.append(
            "access"
        )


    if event_type in NETWORK_EVENTS:

        groups.append(
            "network"
        )


    if event_type in DATA_TRANSFER_EVENTS:

        groups.append(
            "data_transfer"
        )


    return groups


# ==========================================================
# CHECK ENTITY RELATIONSHIP
# ==========================================================

def calculate_entity_similarity(
    event_a: Dict[str, Any],
    event_b: Dict[str, Any]
) -> Dict[str, Any]:

    """
    Check whether two events share security entities.
    """

    score = 0

    shared_entities = []


    # ------------------------------------------------------
    # Same user
    # ------------------------------------------------------

    user_a = str(
        event_a.get(
            "user_id",
            ""
        )
    )

    user_b = str(
        event_b.get(
            "user_id",
            ""
        )
    )


    if (
        user_a
        and
        user_b
        and
        user_a == user_b
    ):

        score += 40

        shared_entities.append(

            {
                "type":
                    "user",

                "value":
                    user_a
            }

        )


    # ------------------------------------------------------
    # Same source IP
    # ------------------------------------------------------

    source_ip_a = str(
        event_a.get(
            "source_ip",
            ""
        )
    )

    source_ip_b = str(
        event_b.get(
            "source_ip",
            ""
        )
    )


    if (
        source_ip_a
        and
        source_ip_b
        and
        source_ip_a == source_ip_b
    ):

        score += 30

        shared_entities.append(

            {
                "type":
                    "source_ip",

                "value":
                    source_ip_a
            }

        )


    # ------------------------------------------------------
    # Same device
    # ------------------------------------------------------

    device_a = str(
        event_a.get(
            "device_id",
            ""
        )
    )

    device_b = str(
        event_b.get(
            "device_id",
            ""
        )
    )


    if (
        device_a
        and
        device_b
        and
        device_a == device_b
    ):

        score += 30

        shared_entities.append(

            {
                "type":
                    "device",

                "value":
                    device_a
            }

        )


    return {

        "similarity_score":
            min(
                score,
                100
            ),

        "shared_entities":
            shared_entities

    }


# ==========================================================
# CHECK TIME PROXIMITY
# ==========================================================

def calculate_time_proximity(
    event_a: Dict[str, Any],
    event_b: Dict[str, Any]
) -> Dict[str, Any]:

    """
    Calculate how close two events occurred in time.
    """

    time_a = parse_timestamp(

        event_a.get(
            "timestamp"
        )

    )


    time_b = parse_timestamp(

        event_b.get(
            "timestamp"
        )

    )


    difference = abs(

        (
            time_b
            -
            time_a
        ).total_seconds()

    )


    minutes = (
        difference
        /
        60
    )


    if minutes <= 5:

        score = 100

    elif minutes <= 15:

        score = 80

    elif minutes <= 30:

        score = 60

    elif minutes <= 60:

        score = 40

    else:

        score = 0


    return {

        "minutes_apart":
            round(
                minutes,
                2
            ),

        "proximity_score":
            score,

        "within_window":
            (
                minutes
                <=
                CORRELATION_WINDOW_MINUTES
            )

    }


# ==========================================================
# DETERMINE IF TWO EVENTS ARE RELATED
# ==========================================================

def are_events_related(
    event_a: Dict[str, Any],
    event_b: Dict[str, Any]
) -> Dict[str, Any]:

    """
    Determine whether two events should be correlated.
    """

    entity_result = calculate_entity_similarity(
        event_a,
        event_b
    )


    time_result = calculate_time_proximity(
        event_a,
        event_b
    )


    entity_score = (
        entity_result[
            "similarity_score"
        ]
    )


    time_score = (
        time_result[
            "proximity_score"
        ]
    )


    correlation_score = round(

        (
            entity_score
            *
            0.7
        )

        +

        (
            time_score
            *
            0.3
        )

    )


    # At least one meaningful shared entity is required.

    is_related = (

        entity_score >= 30

        and

        time_result[
            "within_window"
        ]

        and

        correlation_score >= 40

    )


    return {

        "is_related":
            is_related,

        "correlation_score":
            correlation_score,

        "entity_similarity":
            entity_result,

        "time_proximity":
            time_result

    }


# ==========================================================
# DETECT ATTACK STORY
# ==========================================================

def detect_attack_story(
    events: List[Dict[str, Any]]
) -> Dict[str, Any]:

    """
    Analyze correlated events and identify the strongest
    matching attack story.
    """

    observed_groups = set()


    for event in events:

        groups = get_event_groups(
            event
        )

        observed_groups.update(
            groups
        )


    matched_patterns = []


    for (
        pattern_name,
        pattern_config
    ) in ATTACK_PATTERNS.items():


        required_groups = set(

            pattern_config[
                "required_groups"
            ]

        )


        if required_groups.issubset(
            observed_groups
        ):

            matched_patterns.append(

                {

                    "name":
                        pattern_name,

                    "base_score":
                        pattern_config[
                            "base_score"
                        ],

                    "matched_groups":
                        list(
                            required_groups
                        )

                }

            )


    # ------------------------------------------------------
    # Select strongest pattern
    # ------------------------------------------------------

    if matched_patterns:

        strongest_pattern = max(

            matched_patterns,

            key=lambda pattern:
                pattern[
                    "base_score"
                ]

        )


        attack_story = (

            strongest_pattern[
                "name"
            ]

        )


        pattern_score = (

            strongest_pattern[
                "base_score"
            ]

        )


    else:

        attack_story = (
            "Correlated Suspicious Activity"
        )

        pattern_score = 5


    return {

        "attack_story":
            attack_story,

        "pattern_score":
            pattern_score,

        "observed_groups":
            sorted(
                list(
                    observed_groups
                )
            ),

        "matched_patterns":
            matched_patterns

    }


# ==========================================================
# CREATE TIMELINE
# ==========================================================

def create_timeline(
    events: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:

    """
    Create a chronological incident timeline.
    """

    sorted_events = sorted(

        events,

        key=lambda event:
            parse_timestamp(
                event[
                    "timestamp"
                ]
            )

    )


    timeline = []


    for index, event in enumerate(
        sorted_events,
        start=1
    ):

        timeline.append(

            {

                "sequence":
                    index,

                "event_id":
                    event.get(
                        "event_id"
                    ),

                "timestamp":
                    event.get(
                        "timestamp"
                    ),

                "event_type":
                    event.get(
                        "event_type"
                    ),

                "user_id":
                    event.get(
                        "user_id"
                    ),

                "source_ip":
                    event.get(
                        "source_ip"
                    ),

                "device_id":
                    event.get(
                        "device_id"
                    )

            }

        )


    return timeline


# ==========================================================
# CALCULATE INCIDENT RISK
# ==========================================================

def calculate_incident_risk(
    analyzed_events: List[Dict[str, Any]],
    attack_story_result: Dict[str, Any]
) -> int:

    """
    Calculate incident-level risk using event risks
    and attack-chain context.
    """


    event_risk_scores = [

        analyzed_event[
            "risk_analysis"
        ][
            "final_risk_score"
        ]

        for analyzed_event
        in analyzed_events

    ]


    if not event_risk_scores:

        return 0


    highest_risk = max(
        event_risk_scores
    )


    average_risk = (

        sum(
            event_risk_scores
        )

        /

        len(
            event_risk_scores
        )

    )


    # ------------------------------------------------------
    # Base incident score
    # ------------------------------------------------------

    incident_score = (

        highest_risk
        *
        0.6

        +

        average_risk
        *
        0.4

    )


    # ------------------------------------------------------
    # Multi-event correlation bonus
    # ------------------------------------------------------

    event_count_bonus = min(

        len(
            analyzed_events
        )
        *
        2,

        10

    )


    # ------------------------------------------------------
    # Attack pattern bonus
    # ------------------------------------------------------

    pattern_bonus = (

        attack_story_result[
            "pattern_score"
        ]

    )


    final_score = min(

        round(

            incident_score

            +

            event_count_bonus

            +

            pattern_bonus

        ),

        100

    )


    return final_score


# ==========================================================
# INCIDENT SEVERITY
# ==========================================================

def calculate_incident_severity(
    risk_score: int
) -> str:

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

def calculate_incident_priority(
    risk_score: int
) -> str:

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
# CORRELATE A LIST OF EVENTS
# ==========================================================

def correlate_events(
    events: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:

    """
    Group related events into incidents.
    """


    if not events:

        return []


    # ------------------------------------------------------
    # Sort events chronologically
    # ------------------------------------------------------

    sorted_events = sorted(

        events,

        key=lambda event:
            parse_timestamp(
                event[
                    "timestamp"
                ]
            )

    )


    incident_groups = []


    # ======================================================
    # BUILD CORRELATION GROUPS
    # ======================================================

    for event in sorted_events:


        added_to_group = False


        for group in incident_groups:


            # Compare against every event already in group.

            for existing_event in group:


                relationship = are_events_related(

                    event,

                    existing_event

                )


                if relationship[
                    "is_related"
                ]:

                    group.append(
                        event
                    )

                    added_to_group = True

                    break


            if added_to_group:

                break


        # --------------------------------------------------
        # Start new group
        # --------------------------------------------------

        if not added_to_group:

            incident_groups.append(
                [
                    event
                ]
            )


    # ======================================================
    # BUILD INCIDENT OBJECTS
    # ======================================================

    incidents = []


    incident_number = 1


    for group in incident_groups:


        # --------------------------------------------------
        # Analyze every event
        # --------------------------------------------------

        analyzed_events = []


        for event in group:


            risk_analysis = calculate_risk(
                event
            )


            analyzed_events.append(

                {

                    "event":
                        event,

                    "risk_analysis":
                        risk_analysis

                }

            )


        # --------------------------------------------------
        # Determine attack story
        # --------------------------------------------------

        attack_story_result = detect_attack_story(
            group
        )


        # --------------------------------------------------
        # Calculate incident risk
        # --------------------------------------------------

        incident_risk = calculate_incident_risk(

            analyzed_events,

            attack_story_result

        )


        # --------------------------------------------------
        # Create incident only when meaningful
        # --------------------------------------------------

        contains_high_risk_event = any(

            analyzed_event[
                "risk_analysis"
            ][
                "final_risk_score"
            ]
            >=
            40

            for analyzed_event
            in analyzed_events

        )


        should_create_incident = (

            len(
                group
            )
            >=
            2

            or

            contains_high_risk_event

        )


        if not should_create_incident:

            continue


        # --------------------------------------------------
        # Build incident
        # --------------------------------------------------

        incident_id = (

            f"AEG-INC-"
            f"{incident_number:04d}"

        )


        incident_number += 1


        timeline = create_timeline(
            group
        )


        incident = {

            "incident_id":
                incident_id,

            "title":
                attack_story_result[
                    "attack_story"
                ],

            "status":
                "New",

            "risk_score":
                incident_risk,

            "severity":
                calculate_incident_severity(
                    incident_risk
                ),

            "priority":
                calculate_incident_priority(
                    incident_risk
                ),

            "event_count":
                len(
                    group
                ),

            "first_seen":
                timeline[
                    0
                ][
                    "timestamp"
                ],

            "last_seen":
                timeline[
                    -1
                ][
                    "timestamp"
                ],

            "observed_groups":
                attack_story_result[
                    "observed_groups"
                ],

            "matched_patterns":
                attack_story_result[
                    "matched_patterns"
                ],

            "timeline":
                timeline,

            "events":
                analyzed_events

        }


        incidents.append(
            incident
        )


    # ------------------------------------------------------
    # Sort highest-risk incidents first
    # ------------------------------------------------------

    incidents = sorted(

        incidents,

        key=lambda incident:
            incident[
                "risk_score"
            ],

        reverse=True

    )


    return incidents


# ==========================================================
# DISPLAY INCIDENT
# ==========================================================

def display_incident(
    incident: Dict[str, Any]
):

    """
    Print a readable incident report.
    """


    print(
        "\n"
        "============================================================"
    )

    print(
        f" INCIDENT: "
        f"{incident['incident_id']}"
    )

    print(
        "============================================================"
    )


    print(
        f"\nTitle:        "
        f"{incident['title']}"
    )

    print(
        f"Status:       "
        f"{incident['status']}"
    )

    print(
        f"Risk Score:   "
        f"{incident['risk_score']}/100"
    )

    print(
        f"Severity:     "
        f"{incident['severity']}"
    )

    print(
        f"Priority:     "
        f"{incident['priority']}"
    )

    print(
        f"Events:       "
        f"{incident['event_count']}"
    )

    print(
        f"First Seen:   "
        f"{incident['first_seen']}"
    )

    print(
        f"Last Seen:    "
        f"{incident['last_seen']}"
    )


    print(
        "\nATTACK TIMELINE"
    )

    print(
        "------------------------------------------------------------"
    )


    for timeline_event in incident[
        "timeline"
    ]:


        print(

            f"{timeline_event['sequence']}. "
            f"{timeline_event['timestamp']}  "
            f"{timeline_event['event_type']}"

        )


    print(
        "\nOBSERVED BEHAVIOR GROUPS"
    )

    print(
        "------------------------------------------------------------"
    )


    for group in incident[
        "observed_groups"
    ]:

        print(
            f"• {group}"
        )


    print(
        "\n"
        "============================================================\n"
    )


# ==========================================================
# TEST CORRELATION ENGINE
# ==========================================================

if __name__ == "__main__":


    # ------------------------------------------------------
    # TEST ATTACK CHAIN
    # ------------------------------------------------------

    test_events = [


        # --------------------------------------------------
        # EVENT 1
        # Repeated login failures
        # --------------------------------------------------

        {

            "event_id":
                "EVT-CORR-001",

            "timestamp":
                "2026-07-12 02:51:00",

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
                28,

            "request_count":
                850,

            "bytes_transferred":
                25000,

            "login_hour":
                2,

            "new_device":
                1,

            "privilege_change":
                0,

            "sensitive_resource":
                0,

            "asset_criticality":
                "High"

        },


        # --------------------------------------------------
        # EVENT 2
        # Successful login after suspicious failures
        # --------------------------------------------------

        {

            "event_id":
                "EVT-CORR-002",

            "timestamp":
                "2026-07-12 03:02:00",

            "event_type":
                "successful_login",

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
                0,

            "request_count":
                40,

            "bytes_transferred":
                15000,

            "login_hour":
                3,

            "new_device":
                1,

            "privilege_change":
                0,

            "sensitive_resource":
                0,

            "asset_criticality":
                "High"

        },


        # --------------------------------------------------
        # EVENT 3
        # Privilege change
        # --------------------------------------------------

        {

            "event_id":
                "EVT-CORR-003",

            "timestamp":
                "2026-07-12 03:07:00",

            "event_type":
                "privilege_change",

            "source_ip":
                "203.0.113.45",

            "destination_ip":
                "192.168.1.15",

            "user_id":
                "employee_17",

            "device_id":
                "UNKNOWN-DEVICE",

            "protocol":
                "HTTPS",

            "failed_attempts":
                0,

            "request_count":
                90,

            "bytes_transferred":
                20000,

            "login_hour":
                3,

            "new_device":
                1,

            "privilege_change":
                1,

            "sensitive_resource":
                0,

            "asset_criticality":
                "Critical"

        },


        # --------------------------------------------------
        # EVENT 4
        # Sensitive resource access
        # --------------------------------------------------

        {

            "event_id":
                "EVT-CORR-004",

            "timestamp":
                "2026-07-12 03:14:00",

            "event_type":
                "restricted_resource_access",

            "source_ip":
                "203.0.113.45",

            "destination_ip":
                "192.168.1.20",

            "user_id":
                "employee_17",

            "device_id":
                "UNKNOWN-DEVICE",

            "protocol":
                "HTTPS",

            "failed_attempts":
                0,

            "request_count":
                180,

            "bytes_transferred":
                500000,

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

        },


        # --------------------------------------------------
        # EVENT 5
        # Large data transfer
        # --------------------------------------------------

        {

            "event_id":
                "EVT-CORR-005",

            "timestamp":
                "2026-07-12 03:22:00",

            "event_type":
                "large_data_transfer",

            "source_ip":
                "203.0.113.45",

            "destination_ip":
                "192.168.1.20",

            "user_id":
                "employee_17",

            "device_id":
                "UNKNOWN-DEVICE",

            "protocol":
                "HTTPS",

            "failed_attempts":
                0,

            "request_count":
                500,

            "bytes_transferred":
                190000000,

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

        },


        # --------------------------------------------------
        # UNRELATED NORMAL EVENT
        # --------------------------------------------------

        {

            "event_id":
                "EVT-NORMAL-999",

            "timestamp":
                "2026-07-12 11:30:00",

            "event_type":
                "successful_login",

            "source_ip":
                "192.168.5.20",

            "destination_ip":
                "192.168.1.10",

            "user_id":
                "employee_42",

            "device_id":
                "WORKSTATION-22",

            "protocol":
                "HTTPS",

            "failed_attempts":
                0,

            "request_count":
                35,

            "bytes_transferred":
                12000,

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

    ]


    # ------------------------------------------------------
    # RUN CORRELATION
    # ------------------------------------------------------

    print(
        "\n"
        "============================================================"
    )

    print(
        " AEGIS AI - EVENT CORRELATION TEST"
    )

    print(
        "============================================================"
    )


    print(
        f"\nInput Events: "
        f"{len(test_events)}"
    )


    incidents = correlate_events(
        test_events
    )


    print(
        f"Incidents Created: "
        f"{len(incidents)}"
    )


    for incident in incidents:

        display_incident(
            incident
        )