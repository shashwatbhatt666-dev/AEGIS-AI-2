# ==========================================================
# AEGIS AI - DATABASE LAYER
# ==========================================================

from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

import sqlite3
import json


# ==========================================================
# DATABASE PATH
# ==========================================================

BACKEND_DIR = Path(__file__).resolve().parent

DATABASE_FILE = (
    BACKEND_DIR
    / "aegis.db"
)


# ==========================================================
# DATABASE CONNECTION
# ==========================================================

def get_connection():

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    connection.row_factory = sqlite3.Row

    return connection


# ==========================================================
# INITIALIZE DATABASE
# ==========================================================

def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()


    # ------------------------------------------------------
    # EVENTS TABLE
    # ------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            event_id TEXT UNIQUE NOT NULL,

            timestamp TEXT NOT NULL,

            event_type TEXT,

            source_ip TEXT,

            destination_ip TEXT,

            user_id TEXT,

            device_id TEXT,

            protocol TEXT,

            risk_score INTEGER DEFAULT 0,

            severity TEXT,

            is_anomaly INTEGER DEFAULT 0,

            rule_score INTEGER DEFAULT 0,

            anomaly_score INTEGER DEFAULT 0,

            analysis_json TEXT NOT NULL,

            created_at TEXT NOT NULL

        )
        """
    )


    # ------------------------------------------------------
    # INCIDENTS TABLE
    # ------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id TEXT UNIQUE NOT NULL,

            title TEXT,

            risk_score INTEGER DEFAULT 0,

            severity TEXT,

            priority TEXT,

            status TEXT DEFAULT 'New',

            event_count INTEGER DEFAULT 0,

            first_seen TEXT,

            last_seen TEXT,

            incident_json TEXT NOT NULL,

            created_at TEXT NOT NULL,

            updated_at TEXT NOT NULL

        )
        """
    )


    # ------------------------------------------------------
    # INCIDENT NOTES TABLE
    # ------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_notes (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id TEXT NOT NULL,

            note TEXT NOT NULL,

            analyst TEXT DEFAULT 'SOC Analyst',

            created_at TEXT NOT NULL

        )
        """
    )


    # ------------------------------------------------------
    # INDEXES
    # ------------------------------------------------------

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_events_timestamp
        ON events(timestamp)
        """
    )


    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_events_risk_score
        ON events(risk_score)
        """
    )


    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_events_user_id
        ON events(user_id)
        """
    )


    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_events_source_ip
        ON events(source_ip)
        """
    )


    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_incidents_status
        ON incidents(status)
        """
    )


    connection.commit()

    connection.close()


    print(
        f"AEGIS database initialized: "
        f"{DATABASE_FILE}"
    )


# ==========================================================
# SAVE EVENT
# ==========================================================

def save_event(
    analysis: Dict[str, Any]
):

    event = analysis[
        "event"
    ]

    rule_analysis = analysis[
        "rule_analysis"
    ]

    anomaly_analysis = analysis[
        "anomaly_analysis"
    ]

    risk_analysis = analysis[
        "risk_analysis"
    ]


    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute(
        """
        INSERT OR REPLACE INTO events (

            event_id,
            timestamp,
            event_type,
            source_ip,
            destination_ip,
            user_id,
            device_id,
            protocol,
            risk_score,
            severity,
            is_anomaly,
            rule_score,
            anomaly_score,
            analysis_json,
            created_at

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,

        (

            event.get(
                "event_id"
            ),

            event.get(
                "timestamp"
            ),

            event.get(
                "event_type"
            ),

            event.get(
                "source_ip"
            ),

            event.get(
                "destination_ip"
            ),

            event.get(
                "user_id"
            ),

            event.get(
                "device_id"
            ),

            event.get(
                "protocol"
            ),

            risk_analysis.get(
                "final_risk_score",
                0
            ),

            risk_analysis.get(
                "severity",
                "Informational"
            ),

            int(
                anomaly_analysis.get(
                    "is_anomaly",
                    False
                )
            ),

            rule_analysis.get(
                "rule_score",
                0
            ),

            anomaly_analysis.get(
                "anomaly_score",
                0
            ),

            json.dumps(
                analysis,
                default=str
            ),

            datetime.now().isoformat()

        )

    )


    connection.commit()

    connection.close()


# ==========================================================
# GET EVENTS
# ==========================================================

def get_events_from_database(

    limit: int = 50,

    offset: int = 0,

    severity: Optional[str] = None,

    min_risk: Optional[int] = None,

    event_type: Optional[str] = None,

    search: Optional[str] = None

) -> List[Dict[str, Any]]:


    connection = get_connection()

    cursor = connection.cursor()


    query = """

        SELECT *

        FROM events

        WHERE 1 = 1

    """


    parameters = []


    # ------------------------------------------------------
    # SEVERITY FILTER
    # ------------------------------------------------------

    if severity:

        query += """

            AND LOWER(severity)
            =
            LOWER(?)

        """

        parameters.append(
            severity
        )


    # ------------------------------------------------------
    # MINIMUM RISK FILTER
    # ------------------------------------------------------

    if min_risk is not None:

        query += """

            AND risk_score >= ?

        """

        parameters.append(
            min_risk
        )


    # ------------------------------------------------------
    # EVENT TYPE FILTER
    # ------------------------------------------------------

    if event_type:

        query += """

            AND LOWER(event_type)
            =
            LOWER(?)

        """

        parameters.append(
            event_type
        )


    # ------------------------------------------------------
    # SEARCH
    # ------------------------------------------------------

    if search:

        query += """

            AND (

                event_id LIKE ?

                OR

                user_id LIKE ?

                OR

                source_ip LIKE ?

                OR

                device_id LIKE ?

            )

        """


        search_value = (
            f"%{search}%"
        )


        parameters.extend(

            [

                search_value,

                search_value,

                search_value,

                search_value

            ]

        )


    query += """

        ORDER BY timestamp DESC

        LIMIT ?

        OFFSET ?

    """


    parameters.extend(

        [

            limit,

            offset

        ]

    )


    cursor.execute(

        query,

        parameters

    )


    rows = cursor.fetchall()


    connection.close()


    events = []


    for row in rows:

        try:

            analysis = json.loads(
                row[
                    "analysis_json"
                ]
            )

            events.append(
                analysis
            )

        except Exception:

            continue


    return events


# ==========================================================
# GET RAW EVENTS FOR CORRELATION
# ==========================================================

def get_raw_events_from_database(

    limit: int = 500

) -> List[Dict[str, Any]]:


    analyses = get_events_from_database(

        limit=limit

    )


    return [

        analysis[
            "event"
        ]

        for analysis
        in analyses

        if "event"
        in analysis

    ]


# ==========================================================
# GET SINGLE EVENT
# ==========================================================

def get_event_by_id(

    event_id: str

) -> Optional[Dict[str, Any]]:


    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute(
        """

        SELECT analysis_json

        FROM events

        WHERE event_id = ?

        """,

        (
            event_id,
        )

    )


    row = cursor.fetchone()


    connection.close()


    if not row:

        return None


    return json.loads(

        row[
            "analysis_json"
        ]

    )


# ==========================================================
# SAVE INCIDENT
# ==========================================================

def save_incident(

    incident: Dict[str, Any]

):


    connection = get_connection()

    cursor = connection.cursor()


    now = datetime.now().isoformat()


    # ------------------------------------------------------
    # CHECK EXISTING STATUS
    # ------------------------------------------------------

    cursor.execute(
        """

        SELECT status, created_at

        FROM incidents

        WHERE incident_id = ?

        """,

        (
            incident.get(
                "incident_id"
            ),
        )

    )


    existing = cursor.fetchone()


    if existing:

        status = existing[
            "status"
        ]

        created_at = existing[
            "created_at"
        ]

    else:

        status = incident.get(
            "status",
            "New"
        )

        created_at = now


    incident[
        "status"
    ] = status


    cursor.execute(
        """
        INSERT OR REPLACE INTO incidents (

            incident_id,
            title,
            risk_score,
            severity,
            priority,
            status,
            event_count,
            first_seen,
            last_seen,
            incident_json,
            created_at,
            updated_at

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,

        (

            incident.get(
                "incident_id"
            ),

            incident.get(
                "title"
            ),

            incident.get(
                "risk_score",
                0
            ),

            incident.get(
                "severity"
            ),

            incident.get(
                "priority"
            ),

            status,

            incident.get(
                "event_count",
                0
            ),

            incident.get(
                "first_seen"
            ),

            incident.get(
                "last_seen"
            ),

            json.dumps(
                incident,
                default=str
            ),

            created_at,

            now

        )

    )


    connection.commit()

    connection.close()


# ==========================================================
# GET INCIDENTS
# ==========================================================

def get_incidents_from_database(

    limit: int = 100

) -> List[Dict[str, Any]]:


    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute(
        """

        SELECT
            incident_json,
            status

        FROM incidents

        ORDER BY
            risk_score DESC,
            updated_at DESC

        LIMIT ?

        """,

        (
            limit,
        )

    )


    rows = cursor.fetchall()


    connection.close()


    incidents = []


    for row in rows:

        incident = json.loads(

            row[
                "incident_json"
            ]

        )


        # Always use latest DB status.

        incident[
            "status"
        ] = row[
            "status"
        ]


        incidents.append(
            incident
        )


    return incidents


# ==========================================================
# GET SINGLE INCIDENT
# ==========================================================

def get_incident_by_id(

    incident_id: str

) -> Optional[Dict[str, Any]]:


    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute(
        """

        SELECT
            incident_json,
            status

        FROM incidents

        WHERE incident_id = ?

        """,

        (
            incident_id,
        )

    )


    row = cursor.fetchone()


    connection.close()


    if not row:

        return None


    incident = json.loads(

        row[
            "incident_json"
        ]

    )


    incident[
        "status"
    ] = row[
        "status"
    ]


    return incident


# ==========================================================
# UPDATE INCIDENT STATUS
# ==========================================================

def update_incident_status_in_database(

    incident_id: str,

    status: str

) -> bool:


    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute(
        """

        UPDATE incidents

        SET
            status = ?,
            updated_at = ?

        WHERE incident_id = ?

        """,

        (

            status,

            datetime.now().isoformat(),

            incident_id

        )

    )


    updated = (
        cursor.rowcount
        >
        0
    )


    connection.commit()

    connection.close()


    return updated


# ==========================================================
# ADD INCIDENT NOTE
# ==========================================================

def add_incident_note(

    incident_id: str,

    note: str,

    analyst: str = "SOC Analyst"

):


    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute(
        """

        INSERT INTO incident_notes (

            incident_id,
            note,
            analyst,
            created_at

        )

        VALUES (?, ?, ?, ?)

        """,

        (

            incident_id,

            note,

            analyst,

            datetime.now().isoformat()

        )

    )


    connection.commit()

    connection.close()


# ==========================================================
# GET INCIDENT NOTES
# ==========================================================

def get_incident_notes(

    incident_id: str

) -> List[Dict[str, Any]]:


    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute(
        """

        SELECT *

        FROM incident_notes

        WHERE incident_id = ?

        ORDER BY created_at DESC

        """,

        (
            incident_id,
        )

    )


    rows = cursor.fetchall()


    connection.close()


    return [

        dict(
            row
        )

        for row
        in rows

    ]


# ==========================================================
# DATABASE STATISTICS
# ==========================================================

def get_database_statistics() -> Dict[str, Any]:


    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM events
        """
    )

    total_events = cursor.fetchone()[
        0
    ]


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM events
        WHERE risk_score >= 65
        """
    )

    high_risk_events = cursor.fetchone()[
        0
    ]


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        WHERE status NOT IN ('Resolved', 'Closed')
        """
    )

    active_incidents = cursor.fetchone()[
        0
    ]


    cursor.execute(
        """
        SELECT COUNT(*)
        FROM incidents
        WHERE severity = 'Critical'
        AND status NOT IN ('Resolved', 'Closed')
        """
    )

    critical_incidents = cursor.fetchone()[
        0
    ]


    connection.close()


    return {

        "total_events":
            total_events,

        "high_risk_events":
            high_risk_events,

        "active_incidents":
            active_incidents,

        "critical_incidents":
            critical_incidents

    }


# ==========================================================
# RESET DATABASE
# ==========================================================

def reset_database():

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute(
        "DELETE FROM incident_notes"
    )

    cursor.execute(
        "DELETE FROM incidents"
    )

    cursor.execute(
        "DELETE FROM events"
    )


    connection.commit()

    connection.close()


# ==========================================================
# DIRECT TEST
# ==========================================================

if __name__ == "__main__":

    initialize_database()

    print(
        "Database setup complete."
    )