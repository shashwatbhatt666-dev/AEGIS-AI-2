import csv
import random
from datetime import datetime, timedelta
from pathlib import Path


# ==========================================================
# AEGIS AI - SYNTHETIC SECURITY EVENT DATASET GENERATOR
# ==========================================================

random.seed(42)

DATA_DIR = Path(__file__).resolve().parent
OUTPUT_FILE = DATA_DIR / "security_events.csv"

TOTAL_EVENTS = 1200


USERS = [
    f"employee_{i:02d}"
    for i in range(1, 51)
]

DEVICES = [
    f"WORKSTATION-{i:02d}"
    for i in range(1, 31)
]

PROTOCOLS = [
    "HTTPS",
    "HTTP",
    "SSH",
    "DNS",
    "TCP"
]

ASSET_CRITICALITY = [
    "Low",
    "Medium",
    "High",
    "Critical"
]


EVENT_TYPES = {

    "normal": [
        "successful_login",
        "normal_web_request",
        "file_access",
        "dns_request"
    ],

    "authentication_anomaly": [
        "unusual_login",
        "new_device_login",
        "off_hours_login"
    ],

    "brute_force": [
        "repeated_login_failure"
    ],

    "suspicious_access": [
        "restricted_resource_access",
        "unusual_resource_access"
    ],

    "privilege_escalation": [
        "privilege_change",
        "admin_permission_request"
    ],

    "network_anomaly": [
        "high_request_rate",
        "unusual_network_connection"
    ],

    "data_exfiltration_suspected": [
        "large_data_transfer",
        "sensitive_data_access"
    ]
}


LABEL_WEIGHTS = {

    "normal": 55,

    "authentication_anomaly": 10,

    "brute_force": 10,

    "suspicious_access": 8,

    "privilege_escalation": 6,

    "network_anomaly": 7,

    "data_exfiltration_suspected": 4
}


def random_ip(internal=True):

    if internal:

        return (
            f"192.168."
            f"{random.randint(1, 20)}."
            f"{random.randint(2, 254)}"
        )

    return (
        f"{random.randint(20, 220)}."
        f"{random.randint(1, 254)}."
        f"{random.randint(1, 254)}."
        f"{random.randint(1, 254)}"
    )


def generate_event(event_number, timestamp):

    label = random.choices(
        population=list(LABEL_WEIGHTS.keys()),
        weights=list(LABEL_WEIGHTS.values()),
        k=1
    )[0]

    event_type = random.choice(
        EVENT_TYPES[label]
    )

    user_id = random.choice(USERS)

    device_id = random.choice(DEVICES)

    protocol = random.choice(PROTOCOLS)


    # ------------------------------------------------------
    # DEFAULT NORMAL VALUES
    # ------------------------------------------------------

    source_ip = random_ip(
        internal=True
    )

    destination_ip = random_ip(
        internal=True
    )

    failed_attempts = random.randint(
        0,
        1
    )

    request_count = random.randint(
        5,
        100
    )

    bytes_transferred = random.randint(
        500,
        50000
    )

    login_hour = random.randint(
        8,
        19
    )

    new_device = 0

    privilege_change = 0

    sensitive_resource = 0

    asset_criticality = random.choice(
        [
            "Low",
            "Medium",
            "Medium",
            "High"
        ]
    )


    # ------------------------------------------------------
    # AUTHENTICATION ANOMALY
    # ------------------------------------------------------

    if label == "authentication_anomaly":

        source_ip = random_ip(
            internal=False
        )

        login_hour = random.choice(
            [
                0,
                1,
                2,
                3,
                4,
                5,
                23
            ]
        )

        new_device = random.choice(
            [
                0,
                1,
                1
            ]
        )

        failed_attempts = random.randint(
            1,
            6
        )


    # ------------------------------------------------------
    # BRUTE FORCE
    # ------------------------------------------------------

    elif label == "brute_force":

        source_ip = random_ip(
            internal=False
        )

        failed_attempts = random.randint(
            10,
            60
        )

        request_count = random.randint(
            100,
            700
        )

        login_hour = random.randint(
            0,
            23
        )


    # ------------------------------------------------------
    # SUSPICIOUS ACCESS
    # ------------------------------------------------------

    elif label == "suspicious_access":

        sensitive_resource = 1

        request_count = random.randint(
            80,
            400
        )

        login_hour = random.choice(
            [
                0,
                1,
                2,
                3,
                4,
                22,
                23
            ]
        )

        asset_criticality = random.choice(
            [
                "High",
                "Critical"
            ]
        )


    # ------------------------------------------------------
    # PRIVILEGE ESCALATION
    # ------------------------------------------------------

    elif label == "privilege_escalation":

        privilege_change = 1

        sensitive_resource = random.choice(
            [
                0,
                1
            ]
        )

        asset_criticality = random.choice(
            [
                "High",
                "Critical"
            ]
        )

        request_count = random.randint(
            50,
            250
        )


    # ------------------------------------------------------
    # NETWORK ANOMALY
    # ------------------------------------------------------

    elif label == "network_anomaly":

        source_ip = random_ip(
            internal=False
        )

        request_count = random.randint(
            700,
            5000
        )

        bytes_transferred = random.randint(
            100000,
            5000000
        )


    # ------------------------------------------------------
    # SUSPECTED DATA EXFILTRATION
    # ------------------------------------------------------

    elif label == "data_exfiltration_suspected":

        sensitive_resource = 1

        bytes_transferred = random.randint(
            10000000,
            500000000
        )

        request_count = random.randint(
            100,
            1000
        )

        asset_criticality = random.choice(
            [
                "High",
                "Critical"
            ]
        )

        login_hour = random.choice(
            [
                0,
                1,
                2,
                3,
                4,
                22,
                23
            ]
        )


    return {

        "event_id":
            f"EVT-{event_number:05d}",

        "timestamp":
            timestamp.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "event_type":
            event_type,

        "source_ip":
            source_ip,

        "destination_ip":
            destination_ip,

        "user_id":
            user_id,

        "device_id":
            device_id,

        "protocol":
            protocol,

        "failed_attempts":
            failed_attempts,

        "request_count":
            request_count,

        "bytes_transferred":
            bytes_transferred,

        "login_hour":
            login_hour,

        "new_device":
            new_device,

        "privilege_change":
            privilege_change,

        "sensitive_resource":
            sensitive_resource,

        "asset_criticality":
            asset_criticality,

        "event_label":
            label

    }


def generate_dataset():

    print(
        "\n"
        "========================================"
    )

    print(
        " AEGIS AI - DATASET GENERATOR"
    )

    print(
        "========================================"
    )


    events = []

    current_time = datetime(
        2026,
        1,
        1,
        8,
        0,
        0
    )


    for event_number in range(
        1,
        TOTAL_EVENTS + 1
    ):

        current_time += timedelta(
            seconds=random.randint(
                10,
                300
            )
        )

        event = generate_event(
            event_number,
            current_time
        )

        events.append(
            event
        )


    fieldnames = [

        "event_id",

        "timestamp",

        "event_type",

        "source_ip",

        "destination_ip",

        "user_id",

        "device_id",

        "protocol",

        "failed_attempts",

        "request_count",

        "bytes_transferred",

        "login_hour",

        "new_device",

        "privilege_change",

        "sensitive_resource",

        "asset_criticality",

        "event_label"

    ]


    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        writer.writerows(
            events
        )


    print(
        f"\nGenerated {TOTAL_EVENTS} "
        "security events."
    )

    print(
        f"\nDataset saved to:\n"
        f"{OUTPUT_FILE}"
    )


    # Count event labels

    label_counts = {}

    for event in events:

        label = event[
            "event_label"
        ]

        label_counts[label] = (
            label_counts.get(
                label,
                0
            )
            + 1
        )


    print(
        "\nEVENT DISTRIBUTION"
    )

    print(
        "----------------------------------------"
    )


    for label, count in sorted(
        label_counts.items()
    ):

        print(
            f"{label:<30} {count}"
        )


    print(
        "\n========================================"
    )

    print(
        " DATASET GENERATION COMPLETE"
    )

    print(
        "========================================\n"
    )


if __name__ == "__main__":

    generate_dataset()