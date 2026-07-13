# ==========================================================
# AEGIS AI - FASTAPI BACKEND
# ==========================================================
#
# Intelligent Security Operations, Threat Correlation
# & Behavioral Anomaly Platform
#
# ==========================================================

from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import random
import sys
import uuid

import pandas as pd

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


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
# IMPORT AEGIS ENGINES
# ==========================================================
# ==========================================================
# DATABASE IMPORTS
# ==========================================================

from Detection.rule_engine import analyze_event
from ML.anomaly_detector import analyze_anomaly
from Detection.risk_engine import calculate_risk
from Detection.correlation_engine import correlate_events

from Backend.database import (
    initialize_database,
    save_event,
    get_events_from_database,
    get_raw_events_from_database,
    get_event_by_id,
    save_incident,
    get_incidents_from_database,
    get_incident_by_id,
    update_incident_status_in_database,
    add_incident_note,
    get_incident_notes,
    get_database_statistics,
    reset_database
)
# ==========================================================
# ANALYTICS & ENTITY INTELLIGENCE IMPORTS
# ==========================================================

from Backend.analytics import (
    get_analytics_overview,
    get_severity_distribution,
    get_event_type_distribution,
    get_risk_trend,
    get_top_risky_users,
    get_top_source_ips,
    get_detection_statistics,
    get_user_intelligence,
    get_ip_intelligence,
    get_device_intelligence
)
# ==========================================================
# PROJECT FILES
# ==========================================================

DATA_FILE = (
    PROJECT_DIR
    / "Data"
    / "security_events.csv"
)


# ==========================================================
# CREATE FASTAPI APPLICATION
# ==========================================================

app = FastAPI(

    title="AEGIS AI API",

    description=(
        "Intelligent Security Operations, Threat Correlation "
        "and Behavioral Anomaly Platform"
    ),

    version="1.0.0"

)
initialize_database()

# ==========================================================
# CORS
# ==========================================================
#
# This allows our frontend to communicate with the backend.
#
# For development we allow all origins.
# Later, during deployment, we can restrict this.
#
# ==========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# ==========================================================
# IN-MEMORY APPLICATION STATE
# ==========================================================
#
# For the first working version we keep runtime events and
# incidents in memory.
#
# Later we will replace this with a real database.
#
# ==========================================================

runtime_events: List[Dict[str, Any]] = []

runtime_incidents: List[Dict[str, Any]] = []


# ==========================================================
# PYDANTIC REQUEST MODELS
# ==========================================================

class SecurityEventRequest(BaseModel):

    event_id: Optional[str] = None

    timestamp: Optional[str] = None

    event_type: str = Field(
        default="successful_login"
    )

    source_ip: str = Field(
        default="192.168.1.10"
    )

    destination_ip: str = Field(
        default="192.168.1.20"
    )

    user_id: str = Field(
        default="employee_01"
    )

    device_id: str = Field(
        default="WORKSTATION-01"
    )

    protocol: str = Field(
        default="HTTPS"
    )

    failed_attempts: int = Field(
        default=0,
        ge=0
    )

    request_count: int = Field(
        default=20,
        ge=0
    )

    bytes_transferred: int = Field(
        default=10000,
        ge=0
    )

    login_hour: int = Field(
        default=12,
        ge=0,
        le=23
    )

    new_device: int = Field(
        default=0,
        ge=0,
        le=1
    )

    privilege_change: int = Field(
        default=0,
        ge=0,
        le=1
    )

    sensitive_resource: int = Field(
        default=0,
        ge=0,
        le=1
    )

    asset_criticality: str = Field(
        default="Medium"
    )


class IncidentStatusUpdate(BaseModel):

    status: str
class IncidentNoteRequest(BaseModel):

    note: str = Field(
        ...,
        min_length=1,
        max_length=2000
    )

    analyst: str = Field(
        default="SOC Analyst",
        min_length=1,
        max_length=100
    )

class SimulationRequest(BaseModel):

    scenario: str = Field(
        default="mixed"
    )

    event_count: int = Field(
        default=10,
        ge=1,
        le=100
    )


# ==========================================================
# HELPER - CONVERT REQUEST TO EVENT
# ==========================================================

def prepare_event(
    request: SecurityEventRequest
) -> Dict[str, Any]:

    event = request.model_dump()


    if not event.get(
        "event_id"
    ):

        event[
            "event_id"
        ] = (

            "EVT-LIVE-"

            +

            uuid.uuid4().hex[
                :8
            ].upper()

        )


    if not event.get(
        "timestamp"
    ):

        event[
            "timestamp"
        ] = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )


    return event


# ==========================================================
# HELPER - ANALYZE COMPLETE EVENT
# ==========================================================

def run_complete_analysis(
    event: Dict[str, Any]
) -> Dict[str, Any]:

    # ------------------------------------------------------
    # Rule analysis
    # ------------------------------------------------------

    rule_result = analyze_event(
        event
    )


    # ------------------------------------------------------
    # ML anomaly analysis
    # ------------------------------------------------------

    anomaly_result = analyze_anomaly(
        event
    )


    # ------------------------------------------------------
    # Dynamic risk analysis
    # ------------------------------------------------------

    risk_result = calculate_risk(

        event,

        rule_result=
            rule_result,

        anomaly_result=
            anomaly_result

    )


    return {

        "event":
            event,

        "rule_analysis":
            rule_result,

        "anomaly_analysis":
            anomaly_result,

        "risk_analysis":
            risk_result

    }


# ==========================================================
# HELPER - LOAD DATASET
# ==========================================================

def load_dataset() -> List[Dict[str, Any]]:

    if not DATA_FILE.exists():

        return []


    dataframe = pd.read_csv(
        DATA_FILE
    )


    dataframe = dataframe.fillna(
        ""
    )


    return dataframe.to_dict(
        orient="records"
    )


# ==========================================================
# HELPER - CREATE SIMULATION EVENT
# ==========================================================

def generate_simulation_event(
    scenario: str,
    event_number: int,
    base_time: datetime
) -> Dict[str, Any]:

    scenario = scenario.lower().strip()


    event = {

        "event_id":
            (
                "EVT-SIM-"
                +
                uuid.uuid4().hex[
                    :8
                ].upper()
            ),

        "timestamp":
            (
                base_time
                +
                timedelta(
                    seconds=
                        event_number
                        *
                        random.randint(
                            10,
                            45
                        )
                )
            ).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "event_type":
            "successful_login",

        "source_ip":
            (
                f"192.168."
                f"{random.randint(1, 10)}."
                f"{random.randint(2, 254)}"
            ),

        "destination_ip":
            (
                f"192.168.1."
                f"{random.randint(2, 50)}"
            ),

        "user_id":
            (
                f"employee_"
                f"{random.randint(1, 30):02d}"
            ),

        "device_id":
            (
                f"WORKSTATION-"
                f"{random.randint(1, 30):02d}"
            ),

        "protocol":
            random.choice(
                [
                    "HTTPS",
                    "HTTP",
                    "SSH",
                    "TCP"
                ]
            ),

        "failed_attempts":
            random.randint(
                0,
                1
            ),

        "request_count":
            random.randint(
                10,
                100
            ),

        "bytes_transferred":
            random.randint(
                1000,
                50000
            ),

        "login_hour":
            random.randint(
                8,
                19
            ),

        "new_device":
            0,

        "privilege_change":
            0,

        "sensitive_resource":
            0,

        "asset_criticality":
            random.choice(
                [
                    "Low",
                    "Medium",
                    "High"
                ]
            )

    }


    # ======================================================
    # NORMAL SCENARIO
    # ======================================================

    if scenario == "normal":

        return event


    # ======================================================
    # AUTHENTICATION ANOMALY
    # ======================================================

    if scenario == "authentication":

        event.update(

            {

                "event_type":
                    "repeated_login_failure",

                "source_ip":
                    "203.0.113.45",

                "user_id":
                    "employee_17",

                "device_id":
                    "UNKNOWN-DEVICE",

                "failed_attempts":
                    random.randint(
                        12,
                        45
                    ),

                "request_count":
                    random.randint(
                        150,
                        900
                    ),

                "login_hour":
                    random.choice(
                        [
                            1,
                            2,
                            3,
                            4
                        ]
                    ),

                "new_device":
                    1,

                "asset_criticality":
                    "High"

            }

        )


    # ======================================================
    # NETWORK ANOMALY
    # ======================================================

    elif scenario == "network":

        event.update(

            {

                "event_type":
                    "high_request_rate",

                "source_ip":
                    "198.51.100.24",

                "request_count":
                    random.randint(
                        1500,
                        5000
                    ),

                "bytes_transferred":
                    random.randint(
                        1_000_000,
                        8_000_000
                    ),

                "asset_criticality":
                    "High"

            }

        )


    # ======================================================
    # ACCOUNT COMPROMISE SCENARIO
    # ======================================================

    elif scenario == "account_compromise":

        attack_sequence = [

            "repeated_login_failure",

            "successful_login",

            "privilege_change",

            "restricted_resource_access",

            "large_data_transfer"

        ]


        event_type = attack_sequence[

            event_number

            %

            len(
                attack_sequence
            )

        ]


        event.update(

            {

                "event_type":
                    event_type,

                "source_ip":
                    "203.0.113.45",

                "user_id":
                    "employee_17",

                "device_id":
                    "UNKNOWN-DEVICE",

                "login_hour":
                    3,

                "new_device":
                    1,

                "asset_criticality":
                    "Critical"

            }

        )


        if event_type == "repeated_login_failure":

            event[
                "failed_attempts"
            ] = 32


        elif event_type == "privilege_change":

            event[
                "privilege_change"
            ] = 1


        elif event_type == "restricted_resource_access":

            event[
                "sensitive_resource"
            ] = 1


        elif event_type == "large_data_transfer":

            event[
                "sensitive_resource"
            ] = 1

            event[
                "bytes_transferred"
            ] = 180_000_000


    # ======================================================
    # MIXED SCENARIO
    # ======================================================

    elif scenario == "mixed":

        selected_scenario = random.choice(

            [

                "normal",

                "normal",

                "authentication",

                "network",

                "account_compromise"

            ]

        )


        return generate_simulation_event(

            selected_scenario,

            event_number,

            base_time

        )


    return event


# ==========================================================
# ROOT
# ==========================================================

@app.get(
    "/"
)
def root():

    return {

        "project":
            "AEGIS AI",

        "status":
            "Online",

        "version":
            "1.0.0",

        "message":
            (
                "Intelligent Security Operations, "
                "Threat Correlation & Behavioral "
                "Anomaly Platform"
            )

    }


# ==========================================================
# HEALTH CHECK
# ==========================================================

@app.get(
    "/api/health"
)
def health_check():

    return {

        "success":
            True,

        "status":
            "operational",

        "service":
            "AEGIS AI Backend",

        "timestamp":
            datetime.now().isoformat(),

        "engines":

            {

                "rule_engine":
                    "online",

                "anomaly_engine":
                    "online",

                "risk_engine":
                    "online",

                "correlation_engine":
                    "online"

            }

    }


# ==========================================================
# DASHBOARD
# ==========================================================

@app.get(
    "/api/dashboard"
)
def get_dashboard():


    stats = get_database_statistics()


    posture_penalty = (

        stats[
            "critical_incidents"
        ]
        *
        12

        +

        stats[
            "active_incidents"
        ]
        *
        4

        +

        stats[
            "high_risk_events"
        ]
        *
        2

    )


    security_posture = max(

        0,

        min(

            100,

            100
            -
            posture_penalty

        )

    )


    recent_incidents = get_incidents_from_database(
        limit=5
    )


    recent_events = get_events_from_database(
        limit=10
    )


    return {

        "success":
            True,

        "overview":

            {

                **stats,

                "security_posture":
                    security_posture

            },

        "recent_incidents":
            recent_incidents,

        "recent_events":
            recent_events

    }


# ==========================================================
# GET EVENTS
# ==========================================================

@app.get(
    "/api/events"
)
def get_events(

    limit: int = 50,

    offset: int = 0,

    severity: Optional[str] = None,

    min_risk: Optional[int] = None,

    event_type: Optional[str] = None,

    search: Optional[str] = None

):


    limit = max(
        1,
        min(
            limit,
            500
        )
    )


    offset = max(
        0,
        offset
    )


    events = get_events_from_database(

        limit=
            limit,

        offset=
            offset,

        severity=
            severity,

        min_risk=
            min_risk,

        event_type=
            event_type,

        search=
            search

    )


    return {

        "success":
            True,

        "count":
            len(
                events
            ),

        "limit":
            limit,

        "offset":
            offset,

        "events":
            events

    }
@app.get(
    "/api/events/{event_id}"
)
def get_single_event(
    event_id: str
):


    event = get_event_by_id(
        event_id
    )


    if not event:

        raise HTTPException(

            status_code=404,

            detail="Security event not found"

        )


    return {

        "success":
            True,

        "analysis":
            event

    }

# ==========================================================
# ANALYZE EVENT WITHOUT SAVING
# ==========================================================

@app.post(
    "/api/events/analyze"
)
def analyze_security_event(
    request: SecurityEventRequest
):

    event = prepare_event(
        request
    )


    analysis = run_complete_analysis(
        event
    )


    return {

        "success":
            True,

        "message":
            "Security event analyzed successfully",

        "analysis":
            analysis

    }


# ==========================================================
# SUBMIT AND SAVE EVENT
# ==========================================================

@app.post(
    "/api/events"
)
def submit_security_event(
    request: SecurityEventRequest
):

    event = prepare_event(
        request
    )


    analysis = run_complete_analysis(
        event
    )


    runtime_events.append(
        analysis
    )
    save_event(
    analysis
)



    return {

        "success":
            True,

        "message":
            "Security event submitted and analyzed",

        "analysis":
            analysis

    }


# ==========================================================
# CORRELATE RUNTIME EVENTS
# ==========================================================

@app.post(
    "/api/incidents/correlate"
)
def correlate_runtime_events():

    if not runtime_events:

        return {

            "success":
                True,

            "message":
                "No runtime events available for correlation",

            "incidents_created":
                0,

            "incidents":
                []

        }


    raw_events = get_raw_events_from_database(
    limit=500
)


    incidents = correlate_events(
        raw_events
    )
    for incident in incidents:
     save_incident(
        incident
    )


    # ------------------------------------------------------
    # Preserve existing incident statuses when possible.
    # ------------------------------------------------------

    existing_statuses = {

        incident[
            "incident_id"
        ]:
            incident.get(
                "status",
                "New"
            )

        for incident
        in runtime_incidents

    }


    for incident in incidents:

        if (
            incident[
                "incident_id"
            ]
            in
            existing_statuses
        ):

            incident[
                "status"
            ] = existing_statuses[
                incident[
                    "incident_id"
                ]
            ]


    runtime_incidents.clear()

    runtime_incidents.extend(
        incidents
    )


    return {

        "success":
            True,

        "message":
            "Event correlation completed",

        "incidents_created":
            len(
                incidents
            ),

        "incidents":
            incidents

    }


# ==========================================================
# GET INCIDENTS
# ==========================================================

@app.get(
    "/api/incidents"
)
def get_incidents(

    limit: int = 100

):


    incidents = get_incidents_from_database(

        limit=
            limit

    )


    return {

        "success":
            True,

        "count":
            len(
                incidents
            ),

        "incidents":
            incidents

    }

# ==========================================================
# GET SINGLE INCIDENT
# ==========================================================

@app.get(
    "/api/incidents/{incident_id}"
)
def get_incident(
    incident_id: str
):


    incident = get_incident_by_id(
        incident_id
    )


    if not incident:

        raise HTTPException(

            status_code=404,

            detail="Incident not found"

        )


    notes = get_incident_notes(
        incident_id
    )


    return {

        "success":
            True,

        "incident":
            incident,

        "notes":
            notes

    }


# ==========================================================
# UPDATE INCIDENT STATUS
# ==========================================================

# ==========================================================
# UPDATE INCIDENT STATUS
# ==========================================================
# ==========================================================
# ADD INCIDENT NOTE
# ==========================================================

@app.post(
    "/api/incidents/{incident_id}/notes"
)
def create_incident_note(

    incident_id: str,

    request: IncidentNoteRequest

):

    # ------------------------------------------------------
    # CHECK IF INCIDENT EXISTS
    # ------------------------------------------------------

    incident = get_incident_by_id(
        incident_id
    )


    if not incident:

        raise HTTPException(

            status_code=404,

            detail="Incident not found"

        )


    # ------------------------------------------------------
    # SAVE NOTE TO SQLITE DATABASE
    # ------------------------------------------------------

    add_incident_note(

        incident_id=
            incident_id,

        note=
            request.note,

        analyst=
            request.analyst

    )


    # ------------------------------------------------------
    # GET UPDATED NOTE LIST
    # ------------------------------------------------------

    notes = get_incident_notes(
        incident_id
    )


    # ------------------------------------------------------
    # RETURN RESULT
    # ------------------------------------------------------

    return {

        "success":
            True,

        "message":
            "Incident note added successfully",

        "incident_id":
            incident_id,

        "notes":
            notes

    }
# ==========================================================
# GET INCIDENT NOTES
# ==========================================================

@app.get(
    "/api/incidents/{incident_id}/notes"
)
def read_incident_notes(
    incident_id: str
):

    # ------------------------------------------------------
    # CHECK IF INCIDENT EXISTS
    # ------------------------------------------------------

    incident = get_incident_by_id(
        incident_id
    )


    if not incident:

        raise HTTPException(

            status_code=404,

            detail="Incident not found"

        )


    # ------------------------------------------------------
    # GET NOTES FROM DATABASE
    # ------------------------------------------------------

    notes = get_incident_notes(
        incident_id
    )


    # ------------------------------------------------------
    # RETURN NOTES
    # ------------------------------------------------------

    return {

        "success":
            True,

        "incident_id":
            incident_id,

        "count":
            len(
                notes
            ),

        "notes":
            notes

    }
@app.patch(
    "/api/incidents/{incident_id}/status"
)
def update_incident_status(
    incident_id: str,
    request: IncidentStatusUpdate
):

    # ------------------------------------------------------
    # ALLOWED INCIDENT STATUSES
    # ------------------------------------------------------

    allowed_statuses = [

        "New",
        "Investigating",
        "Contained",
        "Resolved",
        "Closed"

    ]

    # ------------------------------------------------------
    # VALIDATE STATUS
    # ------------------------------------------------------

    if request.status not in allowed_statuses:

        raise HTTPException(

            status_code=400,

            detail=(

                "Invalid status. Allowed values: "

                + ", ".join(
                    allowed_statuses
                )

            )

        )

    # ------------------------------------------------------
    # UPDATE STATUS IN SQLITE DATABASE
    # ------------------------------------------------------

    updated = update_incident_status_in_database(

        incident_id,

        request.status

    )

    # ------------------------------------------------------
    # INCIDENT NOT FOUND
    # ------------------------------------------------------

    if not updated:

        raise HTTPException(

            status_code=404,

            detail="Incident not found"

        )

    # ------------------------------------------------------
    # GET UPDATED INCIDENT
    # ------------------------------------------------------

    incident = get_incident_by_id(
        incident_id
    )

    # ------------------------------------------------------
    # RETURN RESULT
    # ------------------------------------------------------

    return {

        "success":
            True,

        "message":
            "Incident status updated successfully",

        "incident":
            incident

    }


# ==========================================================
# GENERATE SAFE SIMULATION EVENTS
# ==========================================================

@app.post(
    "/api/simulation/generate"
)
def generate_simulation(
    request: SimulationRequest
):

    allowed_scenarios = [

        "normal",

        "authentication",

        "network",

        "account_compromise",

        "mixed"

    ]


    scenario = (
        request.scenario
        .lower()
        .strip()
    )


    if scenario not in allowed_scenarios:

        raise HTTPException(

            status_code=400,

            detail=(

                "Invalid scenario. Allowed scenarios: "

                +

                ", ".join(
                    allowed_scenarios
                )

            )

        )


    base_time = datetime.now()


    generated_analyses = []


    for event_number in range(
        request.event_count
    ):


        event = generate_simulation_event(

            scenario,

            event_number,

            base_time

        )


        analysis = run_complete_analysis(
            event
        )


        runtime_events.append(
            analysis
        )
        save_event(
    analysis
)
        


        generated_analyses.append(
            analysis
        )


    return {

        "success":
            True,

        "message":
            (
                f"Generated "
                f"{request.event_count} "
                f"safe synthetic security events"
            ),

        "scenario":
            scenario,

        "events_generated":
            len(
                generated_analyses
            ),

        "events":
            generated_analyses

    }


# ==========================================================
# RESET RUNTIME DEMO DATA
# ==========================================================
# ==========================================================
# ANALYTICS OVERVIEW
# ==========================================================

@app.get(
    "/api/analytics/overview"
)
def analytics_overview():

    return {

        "success":
            True,

        "analytics":
            get_analytics_overview()

    }


# ==========================================================
# SEVERITY DISTRIBUTION
# ==========================================================

@app.get(
    "/api/analytics/severity-distribution"
)
def analytics_severity_distribution():

    return {

        "success":
            True,

        "data":
            get_severity_distribution()

    }


# ==========================================================
# EVENT TYPE DISTRIBUTION
# ==========================================================

@app.get(
    "/api/analytics/event-types"
)
def analytics_event_types(
    limit: int = 10
):

    limit = max(
        1,
        min(
            limit,
            50
        )
    )

    return {

        "success":
            True,

        "data":
            get_event_type_distribution(
                limit
            )

    }


# ==========================================================
# RISK TREND
# ==========================================================

@app.get(
    "/api/analytics/risk-trend"
)
def analytics_risk_trend(
    limit: int = 50
):

    limit = max(
        1,
        min(
            limit,
            500
        )
    )

    return {

        "success":
            True,

        "data":
            get_risk_trend(
                limit
            )

    }


# ==========================================================
# TOP RISKY USERS
# ==========================================================

@app.get(
    "/api/analytics/top-users"
)
def analytics_top_users(
    limit: int = 10
):

    limit = max(
        1,
        min(
            limit,
            50
        )
    )

    return {

        "success":
            True,

        "data":
            get_top_risky_users(
                limit
            )

    }


# ==========================================================
# TOP SOURCE IP ADDRESSES
# ==========================================================

@app.get(
    "/api/analytics/top-source-ips"
)
def analytics_top_source_ips(
    limit: int = 10
):

    limit = max(
        1,
        min(
            limit,
            50
        )
    )

    return {

        "success":
            True,

        "data":
            get_top_source_ips(
                limit
            )

    }


# ==========================================================
# DETECTION ENGINE STATISTICS
# ==========================================================

@app.get(
    "/api/detections/stats"
)
def detection_statistics():

    return {

        "success":
            True,

        "statistics":
            get_detection_statistics()

    }
# ==========================================================
# USER ENTITY INTELLIGENCE
# ==========================================================

@app.get(
    "/api/entities/users/{user_id}"
)
def user_entity_intelligence(
    user_id: str
):

    # ------------------------------------------------------
    # GET USER INTELLIGENCE
    # ------------------------------------------------------

    intelligence = get_user_intelligence(
        user_id
    )


    # ------------------------------------------------------
    # USER NOT FOUND
    # ------------------------------------------------------

    if not intelligence:

        raise HTTPException(

            status_code=404,

            detail="User entity not found"

        )


    # ------------------------------------------------------
    # RETURN USER PROFILE
    # ------------------------------------------------------

    return {

        "success":
            True,

        "intelligence":
            intelligence

    }


# ==========================================================
# IP ADDRESS ENTITY INTELLIGENCE
# ==========================================================

@app.get(
    "/api/entities/ips/{ip_address}"
)
def ip_entity_intelligence(
    ip_address: str
):

    # ------------------------------------------------------
    # GET IP INTELLIGENCE
    # ------------------------------------------------------

    intelligence = get_ip_intelligence(
        ip_address
    )


    # ------------------------------------------------------
    # IP NOT FOUND
    # ------------------------------------------------------

    if not intelligence:

        raise HTTPException(

            status_code=404,

            detail="IP entity not found"

        )


    # ------------------------------------------------------
    # RETURN IP PROFILE
    # ------------------------------------------------------

    return {

        "success":
            True,

        "intelligence":
            intelligence

    }


# ==========================================================
# DEVICE ENTITY INTELLIGENCE
# ==========================================================

@app.get(
    "/api/entities/devices/{device_id}"
)
def device_entity_intelligence(
    device_id: str
):

    # ------------------------------------------------------
    # GET DEVICE INTELLIGENCE
    # ------------------------------------------------------

    intelligence = get_device_intelligence(
        device_id
    )


    # ------------------------------------------------------
    # DEVICE NOT FOUND
    # ------------------------------------------------------

    if not intelligence:

        raise HTTPException(

            status_code=404,

            detail="Device entity not found"

        )


    # ------------------------------------------------------
    # RETURN DEVICE PROFILE
    # ------------------------------------------------------

    return {

        "success":
            True,

        "intelligence":
            intelligence

    }
# ==========================================================
# RESET AEGIS AI SYSTEM DATA
# ==========================================================

@app.delete(
    "/api/system/reset"
)
def reset_runtime_data():

    # ------------------------------------------------------
    # CLEAR TEMPORARY RUNTIME MEMORY
    # ------------------------------------------------------

    runtime_events.clear()

    runtime_incidents.clear()


    # ------------------------------------------------------
    # CLEAR PERMANENT SQLITE DATABASE
    # ------------------------------------------------------

    reset_database()


    # ------------------------------------------------------
    # RETURN SUCCESS RESPONSE
    # ------------------------------------------------------

    return {

        "success":
            True,

        "message":
            "AEGIS AI runtime and database data cleared successfully",

        "cleared":

            {

                "runtime_events":
                    True,

                "runtime_incidents":
                    True,

                "database_events":
                    True,

                "database_incidents":
                    True,

                "incident_notes":
                    True

            }

    }