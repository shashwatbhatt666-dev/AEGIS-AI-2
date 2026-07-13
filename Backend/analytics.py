# ==========================================================
# AEGIS AI - ANALYTICS & ENTITY INTELLIGENCE ENGINE
# ==========================================================

from typing import Dict, Any, List, Optional
from collections import Counter, defaultdict
from datetime import datetime

import json

from Backend.database import get_connection


# ==========================================================
# HELPER - SAFE JSON LOAD
# ==========================================================

def safe_json_load(value):

    try:
        return json.loads(value)

    except Exception:
        return {}


# ==========================================================
# ANALYTICS OVERVIEW
# ==========================================================

def get_analytics_overview() -> Dict[str, Any]:

    connection = get_connection()
    cursor = connection.cursor()

    # Total events
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM events
        """
    )

    total_events = cursor.fetchone()[0]

    # High risk events
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM events
        WHERE risk_score >= 65
        """
    )

    high_risk_events = cursor.fetchone()[0]

    # Critical events
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM events
        WHERE LOWER(severity) = 'critical'
        """
    )

    critical_events = cursor.fetchone()[0]

    # Anomalies
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM events
        WHERE is_anomaly = 1
        """
    )

    anomalies = cursor.fetchone()[0]

    # Average risk
    cursor.execute(
        """
        SELECT AVG(risk_score)
        FROM events
        """
    )

    average_risk = cursor.fetchone()[0] or 0

    # Total incidents
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        """
    )

    total_incidents = cursor.fetchone()[0]

    # Active incidents
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        WHERE status NOT IN ('Resolved', 'Closed')
        """
    )

    active_incidents = cursor.fetchone()[0]

    connection.close()

    anomaly_rate = 0

    if total_events > 0:

        anomaly_rate = round(
            (anomalies / total_events) * 100,
            2
        )

    return {

        "total_events":
            total_events,

        "high_risk_events":
            high_risk_events,

        "critical_events":
            critical_events,

        "anomalies":
            anomalies,

        "anomaly_rate":
            anomaly_rate,

        "average_risk":
            round(
                float(average_risk),
                2
            ),

        "total_incidents":
            total_incidents,

        "active_incidents":
            active_incidents

    }


# ==========================================================
# SEVERITY DISTRIBUTION
# ==========================================================

def get_severity_distribution() -> List[Dict[str, Any]]:

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            severity,
            COUNT(*) AS total

        FROM events

        GROUP BY severity

        ORDER BY total DESC
        """
    )

    rows = cursor.fetchall()

    connection.close()

    return [

        {

            "severity":
                row["severity"]
                or
                "Unknown",

            "count":
                row["total"]

        }

        for row in rows

    ]


# ==========================================================
# EVENT TYPE DISTRIBUTION
# ==========================================================

def get_event_type_distribution(

    limit: int = 10

) -> List[Dict[str, Any]]:

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            event_type,
            COUNT(*) AS total,
            AVG(risk_score) AS average_risk

        FROM events

        GROUP BY event_type

        ORDER BY total DESC

        LIMIT ?
        """,

        (
            limit,
        )

    )

    rows = cursor.fetchall()

    connection.close()

    return [

        {

            "event_type":
                row["event_type"]
                or
                "unknown",

            "count":
                row["total"],

            "average_risk":
                round(
                    float(
                        row["average_risk"]
                        or
                        0
                    ),
                    2
                )

        }

        for row in rows

    ]


# ==========================================================
# RISK TREND
# ==========================================================

def get_risk_trend(

    limit: int = 50

) -> List[Dict[str, Any]]:

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            timestamp,
            risk_score,
            severity,
            event_type

        FROM events

        ORDER BY timestamp ASC

        LIMIT ?
        """,

        (
            limit,
        )

    )

    rows = cursor.fetchall()

    connection.close()

    return [

        {

            "timestamp":
                row["timestamp"],

            "risk_score":
                row["risk_score"],

            "severity":
                row["severity"],

            "event_type":
                row["event_type"]

        }

        for row in rows

    ]


# ==========================================================
# TOP RISKY USERS
# ==========================================================

def get_top_risky_users(

    limit: int = 10

) -> List[Dict[str, Any]]:

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            user_id,
            COUNT(*) AS event_count,
            AVG(risk_score) AS average_risk,
            MAX(risk_score) AS maximum_risk,
            SUM(
                CASE
                    WHEN risk_score >= 65
                    THEN 1
                    ELSE 0
                END
            ) AS high_risk_events

        FROM events

        WHERE user_id IS NOT NULL
        AND user_id != ''

        GROUP BY user_id

        ORDER BY
            maximum_risk DESC,
            average_risk DESC

        LIMIT ?
        """,

        (
            limit,
        )

    )

    rows = cursor.fetchall()

    connection.close()

    return [

        {

            "user_id":
                row["user_id"],

            "event_count":
                row["event_count"],

            "average_risk":
                round(
                    float(
                        row["average_risk"]
                        or
                        0
                    ),
                    2
                ),

            "maximum_risk":
                row["maximum_risk"],

            "high_risk_events":
                row["high_risk_events"]

        }

        for row in rows

    ]


# ==========================================================
# TOP SOURCE IPS
# ==========================================================

def get_top_source_ips(

    limit: int = 10

) -> List[Dict[str, Any]]:

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            source_ip,
            COUNT(*) AS event_count,
            AVG(risk_score) AS average_risk,
            MAX(risk_score) AS maximum_risk

        FROM events

        WHERE source_ip IS NOT NULL
        AND source_ip != ''

        GROUP BY source_ip

        ORDER BY
            maximum_risk DESC,
            event_count DESC

        LIMIT ?
        """,

        (
            limit,
        )

    )

    rows = cursor.fetchall()

    connection.close()

    return [

        {

            "source_ip":
                row["source_ip"],

            "event_count":
                row["event_count"],

            "average_risk":
                round(
                    float(
                        row["average_risk"]
                        or
                        0
                    ),
                    2
                ),

            "maximum_risk":
                row["maximum_risk"]

        }

        for row in rows

    ]


# ==========================================================
# DETECTION ENGINE STATISTICS
# ==========================================================

def get_detection_statistics() -> Dict[str, Any]:

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            COUNT(*) AS total_events,

            SUM(
                CASE
                    WHEN rule_score > 0
                    THEN 1
                    ELSE 0
                END
            ) AS rule_detections,

            SUM(
                CASE
                    WHEN is_anomaly = 1
                    THEN 1
                    ELSE 0
                END
            ) AS anomaly_detections,

            AVG(rule_score) AS average_rule_score,

            AVG(anomaly_score) AS average_anomaly_score

        FROM events
        """
    )

    row = cursor.fetchone()

    connection.close()

    total_events = row["total_events"] or 0

    rule_detections = (
        row["rule_detections"]
        or
        0
    )

    anomaly_detections = (
        row["anomaly_detections"]
        or
        0
    )

    return {

        "total_events":
            total_events,

        "rule_engine":

            {

                "detections":
                    rule_detections,

                "average_score":
                    round(
                        float(
                            row["average_rule_score"]
                            or
                            0
                        ),
                        2
                    )

            },

        "anomaly_engine":

            {

                "detections":
                    anomaly_detections,

                "average_score":
                    round(
                        float(
                            row["average_anomaly_score"]
                            or
                            0
                        ),
                        2
                    )

            }

    }


# ==========================================================
# USER ENTITY INTELLIGENCE
# ==========================================================

def get_user_intelligence(

    user_id: str

) -> Optional[Dict[str, Any]]:

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *

        FROM events

        WHERE user_id = ?

        ORDER BY timestamp DESC
        """,

        (
            user_id,
        )

    )

    rows = cursor.fetchall()

    connection.close()

    if not rows:

        return None

    source_ips = set()
    devices = set()
    event_types = Counter()

    risk_scores = []

    high_risk_events = 0
    critical_events = 0
    anomalies = 0

    recent_events = []

    for row in rows:

        if row["source_ip"]:

            source_ips.add(
                row["source_ip"]
            )

        if row["device_id"]:

            devices.add(
                row["device_id"]
            )

        if row["event_type"]:

            event_types[
                row["event_type"]
            ] += 1

        risk_score = (
            row["risk_score"]
            or
            0
        )

        risk_scores.append(
            risk_score
        )

        if risk_score >= 65:

            high_risk_events += 1

        if (
            str(
                row["severity"]
            ).lower()
            ==
            "critical"
        ):

            critical_events += 1

        if row["is_anomaly"]:

            anomalies += 1

        if len(recent_events) < 10:

            recent_events.append(

                {

                    "event_id":
                        row["event_id"],

                    "timestamp":
                        row["timestamp"],

                    "event_type":
                        row["event_type"],

                    "source_ip":
                        row["source_ip"],

                    "risk_score":
                        risk_score,

                    "severity":
                        row["severity"]

                }

            )

    maximum_risk = max(
        risk_scores
    )

    average_risk = round(

        sum(
            risk_scores
        )
        /
        len(
            risk_scores
        ),

        2

    )

    # ------------------------------------------------------
    # ENTITY RISK LEVEL
    # ------------------------------------------------------

    if maximum_risk >= 90:

        entity_risk_level = "Critical"

    elif maximum_risk >= 70:

        entity_risk_level = "High"

    elif maximum_risk >= 40:

        entity_risk_level = "Medium"

    else:

        entity_risk_level = "Low"

    return {

        "entity_type":
            "user",

        "entity_id":
            user_id,

        "risk_profile":

            {

                "risk_level":
                    entity_risk_level,

                "maximum_risk":
                    maximum_risk,

                "average_risk":
                    average_risk

            },

        "statistics":

            {

                "total_events":
                    len(
                        rows
                    ),

                "high_risk_events":
                    high_risk_events,

                "critical_events":
                    critical_events,

                "anomalies":
                    anomalies

            },

        "associations":

            {

                "source_ips":
                    sorted(
                        source_ips
                    ),

                "devices":
                    sorted(
                        devices
                    )

            },

        "top_event_types":

            [

                {

                    "event_type":
                        event_type,

                    "count":
                        count

                }

                for event_type, count
                in event_types.most_common(
                    5
                )

            ],

        "recent_events":
            recent_events

    }


# ==========================================================
# IP ENTITY INTELLIGENCE
# ==========================================================

def get_ip_intelligence(

    ip_address: str

) -> Optional[Dict[str, Any]]:

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *

        FROM events

        WHERE source_ip = ?

        ORDER BY timestamp DESC
        """,

        (
            ip_address,
        )

    )

    rows = cursor.fetchall()

    connection.close()

    if not rows:

        return None

    users = set()
    devices = set()
    destinations = set()
    event_types = Counter()

    risk_scores = []

    anomaly_count = 0

    recent_events = []

    for row in rows:

        if row["user_id"]:

            users.add(
                row["user_id"]
            )

        if row["device_id"]:

            devices.add(
                row["device_id"]
            )

        if row["destination_ip"]:

            destinations.add(
                row["destination_ip"]
            )

        if row["event_type"]:

            event_types[
                row["event_type"]
            ] += 1

        risk_score = (
            row["risk_score"]
            or
            0
        )

        risk_scores.append(
            risk_score
        )

        if row["is_anomaly"]:

            anomaly_count += 1

        if len(recent_events) < 10:

            recent_events.append(

                {

                    "event_id":
                        row["event_id"],

                    "timestamp":
                        row["timestamp"],

                    "event_type":
                        row["event_type"],

                    "user_id":
                        row["user_id"],

                    "risk_score":
                        risk_score,

                    "severity":
                        row["severity"]

                }

            )

    maximum_risk = max(
        risk_scores
    )

    average_risk = round(

        sum(
            risk_scores
        )
        /
        len(
            risk_scores
        ),

        2

    )

    return {

        "entity_type":
            "ip_address",

        "entity_id":
            ip_address,

        "risk_profile":

            {

                "maximum_risk":
                    maximum_risk,

                "average_risk":
                    average_risk

            },

        "statistics":

            {

                "total_events":
                    len(
                        rows
                    ),

                "anomalies":
                    anomaly_count

            },

        "associations":

            {

                "users":
                    sorted(
                        users
                    ),

                "devices":
                    sorted(
                        devices
                    ),

                "destination_ips":
                    sorted(
                        destinations
                    )

            },

        "top_event_types":

            [

                {

                    "event_type":
                        event_type,

                    "count":
                        count

                }

                for event_type, count
                in event_types.most_common(
                    5
                )

            ],

        "recent_events":
            recent_events

    }


# ==========================================================
# DEVICE ENTITY INTELLIGENCE
# ==========================================================

def get_device_intelligence(

    device_id: str

) -> Optional[Dict[str, Any]]:

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *

        FROM events

        WHERE device_id = ?

        ORDER BY timestamp DESC
        """,

        (
            device_id,
        )

    )

    rows = cursor.fetchall()

    connection.close()

    if not rows:

        return None

    users = set()
    source_ips = set()
    event_types = Counter()

    risk_scores = []

    anomalies = 0

    recent_events = []

    for row in rows:

        if row["user_id"]:

            users.add(
                row["user_id"]
            )

        if row["source_ip"]:

            source_ips.add(
                row["source_ip"]
            )

        if row["event_type"]:

            event_types[
                row["event_type"]
            ] += 1

        risk_score = (
            row["risk_score"]
            or
            0
        )

        risk_scores.append(
            risk_score
        )

        if row["is_anomaly"]:

            anomalies += 1

        if len(recent_events) < 10:

            recent_events.append(

                {

                    "event_id":
                        row["event_id"],

                    "timestamp":
                        row["timestamp"],

                    "event_type":
                        row["event_type"],

                    "user_id":
                        row["user_id"],

                    "source_ip":
                        row["source_ip"],

                    "risk_score":
                        risk_score,

                    "severity":
                        row["severity"]

                }

            )

    return {

        "entity_type":
            "device",

        "entity_id":
            device_id,

        "risk_profile":

            {

                "maximum_risk":
                    max(
                        risk_scores
                    ),

                "average_risk":
                    round(

                        sum(
                            risk_scores
                        )
                        /
                        len(
                            risk_scores
                        ),

                        2

                    )

            },

        "statistics":

            {

                "total_events":
                    len(
                        rows
                    ),

                "anomalies":
                    anomalies

            },

        "associations":

            {

                "users":
                    sorted(
                        users
                    ),

                "source_ips":
                    sorted(
                        source_ips
                    )

            },

        "top_event_types":

            [

                {

                    "event_type":
                        event_type,

                    "count":
                        count

                }

                for event_type, count
                in event_types.most_common(
                    5
                )

            ],

        "recent_events":
            recent_events

    }