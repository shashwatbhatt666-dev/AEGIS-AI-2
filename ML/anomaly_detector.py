# ==========================================================
# AEGIS AI - BEHAVIORAL ANOMALY DETECTION ENGINE
# ==========================================================
#
# Purpose:
# Train an unsupervised Isolation Forest model on normal
# security behavior and detect unusual security events.
#
# The model analyzes:
# - Failed authentication attempts
# - Request volume
# - Data transfer volume
# - Login hour
# - New device usage
# - Privilege changes
# - Sensitive resource access
# - Asset criticality
#
# ==========================================================


from pathlib import Path
from typing import Dict, Any

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# ==========================================================
# PROJECT PATHS
# ==========================================================

ML_DIR = Path(__file__).resolve().parent

PROJECT_DIR = ML_DIR.parent

DATA_FILE = (
    PROJECT_DIR
    / "Data"
    / "security_events.csv"
)

MODELS_DIR = (
    PROJECT_DIR
    / "Models"
)

MODEL_FILE = (
    MODELS_DIR
    / "anomaly_model.pkl"
)

SCALER_FILE = (
    MODELS_DIR
    / "anomaly_scaler.pkl"
)


# ==========================================================
# MODEL FEATURES
# ==========================================================

FEATURE_COLUMNS = [

    "failed_attempts",

    "request_count",

    "bytes_transferred",

    "login_hour",

    "new_device",

    "privilege_change",

    "sensitive_resource",

    "asset_criticality_score"

]


# ==========================================================
# ASSET CRITICALITY ENCODING
# ==========================================================

ASSET_CRITICALITY_MAP = {

    "low": 1,

    "medium": 2,

    "high": 3,

    "critical": 4

}


# ==========================================================
# CONVERT ASSET CRITICALITY
# ==========================================================

def encode_asset_criticality(
    value: Any
) -> int:

    """
    Convert text asset criticality into a numerical value.
    """

    value = str(
        value
    ).strip().lower()

    return ASSET_CRITICALITY_MAP.get(
        value,
        1
    )


# ==========================================================
# PREPARE DATASET
# ==========================================================

def prepare_dataset(
    dataframe: pd.DataFrame
) -> pd.DataFrame:

    """
    Convert the raw security dataset into numerical
    features that can be used by the ML model.
    """

    data = dataframe.copy()


    # Convert asset criticality to numerical values

    data[
        "asset_criticality_score"
    ] = data[
        "asset_criticality"
    ].apply(
        encode_asset_criticality
    )


    # Ensure all ML features are numerical

    for column in FEATURE_COLUMNS:

        data[column] = pd.to_numeric(
            data[column],
            errors="coerce"
        ).fillna(
            0
        )


    return data[
        FEATURE_COLUMNS
    ]


# ==========================================================
# TRAIN ANOMALY MODEL
# ==========================================================

def train_anomaly_model():

    """
    Train Isolation Forest using normal security events.
    """

    print(
        "\n"
        "=========================================="
    )

    print(
        " AEGIS AI - ANOMALY MODEL TRAINING"
    )

    print(
        "=========================================="
    )


    # ------------------------------------------------------
    # Check dataset
    # ------------------------------------------------------

    if not DATA_FILE.exists():

        raise FileNotFoundError(

            "\nDataset not found:\n"
            f"{DATA_FILE}\n\n"
            "Run this first:\n"
            "python Data/generate_dataset.py"

        )


    # ------------------------------------------------------
    # Load dataset
    # ------------------------------------------------------

    print(
        "\n[1/5] Loading security dataset..."
    )

    dataframe = pd.read_csv(
        DATA_FILE
    )

    print(
        f"      Total events: "
        f"{len(dataframe)}"
    )


    # ------------------------------------------------------
    # Train primarily on NORMAL behavior
    # ------------------------------------------------------

    print(
        "\n[2/5] Selecting normal behavior..."
    )

    normal_data = dataframe[

        dataframe[
            "event_label"
        ] == "normal"

    ].copy()


    if len(normal_data) < 50:

        raise ValueError(

            "Not enough normal events "
            "to train the anomaly model."

        )


    print(
        f"      Normal training events: "
        f"{len(normal_data)}"
    )


    # ------------------------------------------------------
    # Prepare numerical features
    # ------------------------------------------------------

    print(
        "\n[3/5] Preparing behavioral features..."
    )

    X_normal = prepare_dataset(
        normal_data
    )


    # ------------------------------------------------------
    # Scale features
    # ------------------------------------------------------

    print(
        "\n[4/5] Scaling features..."
    )

    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(
        X_normal
    )


    # ------------------------------------------------------
    # Train Isolation Forest
    # ------------------------------------------------------

    print(
        "\n[5/5] Training Isolation Forest..."
    )

    model = IsolationForest(

        n_estimators=250,

        contamination=0.05,

        random_state=42,

        n_jobs=-1

    )


    model.fit(
        X_scaled
    )


    # ------------------------------------------------------
    # Save model files
    # ------------------------------------------------------

    MODELS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    joblib.dump(
        model,
        MODEL_FILE
    )


    joblib.dump(
        scaler,
        SCALER_FILE
    )


    print(
        "\n------------------------------------------"
    )

    print(
        "TRAINING COMPLETE"
    )

    print(
        "------------------------------------------"
    )

    print(
        f"\nModel saved to:\n"
        f"{MODEL_FILE}"
    )

    print(
        f"\nScaler saved to:\n"
        f"{SCALER_FILE}"
    )


    return model, scaler


# ==========================================================
# LOAD TRAINED MODEL
# ==========================================================

def load_anomaly_model():

    """
    Load the trained Isolation Forest model and scaler.
    """

    if (
        not MODEL_FILE.exists()
        or
        not SCALER_FILE.exists()
    ):

        print(
            "\nNo trained anomaly model found."
        )

        print(
            "Training a new model..."
        )

        return train_anomaly_model()


    model = joblib.load(
        MODEL_FILE
    )

    scaler = joblib.load(
        SCALER_FILE
    )


    return model, scaler


# ==========================================================
# PREPARE A SINGLE EVENT
# ==========================================================

def prepare_single_event(
    event: Dict[str, Any]
) -> pd.DataFrame:

    """
    Convert one security event into the same feature
    structure used during model training.
    """

    event_data = {

        "failed_attempts":
            int(
                event.get(
                    "failed_attempts",
                    0
                )
            ),

        "request_count":
            int(
                event.get(
                    "request_count",
                    0
                )
            ),

        "bytes_transferred":
            int(
                event.get(
                    "bytes_transferred",
                    0
                )
            ),

        "login_hour":
            int(
                event.get(
                    "login_hour",
                    12
                )
            ),

        "new_device":
            int(
                event.get(
                    "new_device",
                    0
                )
            ),

        "privilege_change":
            int(
                event.get(
                    "privilege_change",
                    0
                )
            ),

        "sensitive_resource":
            int(
                event.get(
                    "sensitive_resource",
                    0
                )
            ),

        "asset_criticality_score":
            encode_asset_criticality(

                event.get(
                    "asset_criticality",
                    "Low"
                )

            )

    }


    return pd.DataFrame(
        [
            event_data
        ],
        columns=FEATURE_COLUMNS
    )


# ==========================================================
# CONVERT MODEL SCORE TO ANOMALY SCORE
# ==========================================================

def calculate_anomaly_score(
    decision_score: float
) -> int:

    """
    Convert the Isolation Forest decision score into
    a simple 0-100 anomaly score.

    Higher score = more unusual behavior.
    """

    # Isolation Forest:
    # Positive values are generally more normal.
    # Negative values are generally more anomalous.

    anomaly_score = int(

        np.clip(

            50 - (
                decision_score * 250
            ),

            0,

            100

        )

    )


    return anomaly_score


# ==========================================================
# ANOMALY SEVERITY
# ==========================================================

def calculate_anomaly_severity(
    anomaly_score: int
) -> str:

    """
    Convert anomaly score into severity.
    """

    if anomaly_score >= 85:

        return "Critical"

    elif anomaly_score >= 70:

        return "High"

    elif anomaly_score >= 50:

        return "Medium"

    elif anomaly_score >= 30:

        return "Low"

    return "Normal"


# ==========================================================
# ANALYZE ONE SECURITY EVENT
# ==========================================================

def analyze_anomaly(
    event: Dict[str, Any]
) -> Dict[str, Any]:

    """
    Analyze one event using the trained anomaly model.
    """

    model, scaler = load_anomaly_model()


    # Prepare event

    event_dataframe = prepare_single_event(
        event
    )


    # Scale event

    event_scaled = scaler.transform(
        event_dataframe
    )


    # Isolation Forest prediction:
    #
    #  1 = normal
    # -1 = anomaly

    prediction = int(

        model.predict(
            event_scaled
        )[0]

    )


    # Get raw decision score

    decision_score = float(

        model.decision_function(
            event_scaled
        )[0]

    )


    # Convert to readable anomaly score

    anomaly_score = calculate_anomaly_score(
        decision_score
    )


    # Determine anomaly status

    is_anomaly = (
        prediction == -1
    )


    # Calculate severity

    severity = calculate_anomaly_severity(
        anomaly_score
    )


    # ------------------------------------------------------
    # Build explainable behavioral signals
    # ------------------------------------------------------

    behavioral_signals = []


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


    if failed_attempts >= 5:

        behavioral_signals.append(

            "Elevated authentication failure activity"

        )


    if request_count >= 700:

        behavioral_signals.append(

            "Unusually high request volume"

        )


    if bytes_transferred >= 1_000_000:

        behavioral_signals.append(

            "Elevated data transfer volume"

        )


    if login_hour < 6 or login_hour >= 22:

        behavioral_signals.append(

            "Activity outside normal business hours"

        )


    if new_device == 1:

        behavioral_signals.append(

            "Activity from a new or unfamiliar device"

        )


    if privilege_change == 1:

        behavioral_signals.append(

            "Privilege modification behavior"

        )


    if sensitive_resource == 1:

        behavioral_signals.append(

            "Sensitive resource involvement"

        )


    if not behavioral_signals:

        behavioral_signals.append(

            "No obvious rule-level behavioral deviation"

        )


    # ------------------------------------------------------
    # Return result
    # ------------------------------------------------------

    return {

        "event_id":
            str(
                event.get(
                    "event_id",
                    "UNKNOWN"
                )
            ),

        "is_anomaly":
            is_anomaly,

        "model_prediction":
            prediction,

        "decision_score":
            round(
                decision_score,
                6
            ),

        "anomaly_score":
            anomaly_score,

        "severity":
            severity,

        "behavioral_signals":
            behavioral_signals

    }


# ==========================================================
# TEST ANOMALY DETECTOR
# ==========================================================

if __name__ == "__main__":

    # ------------------------------------------------------
    # Train / load model
    # ------------------------------------------------------

    model, scaler = load_anomaly_model()


    # ------------------------------------------------------
    # TEST 1 - NORMAL EVENT
    # ------------------------------------------------------

    normal_event = {

        "event_id":
            "EVT-NORMAL-001",

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


    # ------------------------------------------------------
    # TEST 2 - SUSPICIOUS EVENT
    # ------------------------------------------------------

    suspicious_event = {

        "event_id":
            "EVT-ANOMALY-001",

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


    # ------------------------------------------------------
    # Analyze events
    # ------------------------------------------------------

    normal_result = analyze_anomaly(
        normal_event
    )

    suspicious_result = analyze_anomaly(
        suspicious_event
    )


    # ------------------------------------------------------
    # Display results
    # ------------------------------------------------------

    print(
        "\n"
        "=========================================="
    )

    print(
        " AEGIS AI - ANOMALY DETECTION TEST"
    )

    print(
        "=========================================="
    )


    print(
        "\nNORMAL EVENT"
    )

    print(
        "------------------------------------------"
    )

    print(
        f"Event ID: "
        f"{normal_result['event_id']}"
    )

    print(
        f"Anomaly: "
        f"{normal_result['is_anomaly']}"
    )

    print(
        f"Anomaly Score: "
        f"{normal_result['anomaly_score']}/100"
    )

    print(
        f"Severity: "
        f"{normal_result['severity']}"
    )


    print(
        "\nSUSPICIOUS EVENT"
    )

    print(
        "------------------------------------------"
    )

    print(
        f"Event ID: "
        f"{suspicious_result['event_id']}"
    )

    print(
        f"Anomaly: "
        f"{suspicious_result['is_anomaly']}"
    )

    print(
        f"Anomaly Score: "
        f"{suspicious_result['anomaly_score']}/100"
    )

    print(
        f"Severity: "
        f"{suspicious_result['severity']}"
    )


    print(
        "\nBEHAVIORAL SIGNALS"
    )

    print(
        "------------------------------------------"
    )


    for signal in suspicious_result[
        "behavioral_signals"
    ]:

        print(
            f"• {signal}"
        )


    print(
        "\n"
        "==========================================\n"
    )