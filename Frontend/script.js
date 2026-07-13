/* =========================================================
   AEGIS AI — SECURITY OPERATIONS CENTER
   FRONTEND APPLICATION
========================================================= */


/* =========================================================
   CONFIGURATION
========================================================= */

const API_BASE_URL = "http://127.0.0.1:8000";


/* =========================================================
   APPLICATION STATE
========================================================= */

const state = {

    currentSection: "dashboard",

    events: [],

    incidents: [],

    selectedIncidentId: null,

    selectedEntityType: "users",

    selectedScenario: "account_compromise",

    charts: {
        riskTrend: null,
        severity: null,
        eventTypes: null
    }

};


/* =========================================================
   SCENARIO INFORMATION
========================================================= */

const scenarioInformation = {

    normal: {
        title: "Normal Activity",
        description:
            "Generate routine enterprise security activity."
    },

    authentication: {
        title: "Authentication Attack",
        description:
            "Generate abnormal authentication and login activity."
    },

    network: {
        title: "Network Anomaly",
        description:
            "Generate unusual network communication patterns."
    },

    account_compromise: {
        title: "Account Compromise",
        description:
            "Generate a multi-stage synthetic account compromise sequence."
    },

    mixed: {
        title: "Mixed Environment",
        description:
            "Generate a mixture of normal and suspicious security activity."
    }

};


/* =========================================================
   DOM READY
========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    initializeApplication
);


/* =========================================================
   INITIALIZE APPLICATION
========================================================= */

async function initializeApplication() {

    setupNavigation();

    setupEntityTypeSelector();

    setupScenarioSelector();

    setupRefreshButton();

    setupMobileMenu();

    setupEventSearch();

    configureChartDefaults();

    await checkBackendHealth();

    await refreshAllData();

}


/* =========================================================
   API REQUEST HELPER
========================================================= */

async function apiRequest(
    endpoint,
    options = {}
) {

    try {

        const response = await fetch(

            `${API_BASE_URL}${endpoint}`,

            {
                headers: {
                    "Content-Type": "application/json",
                    ...(options.headers || {})
                },

                ...options
            }

        );


        let data = null;


        try {

            data = await response.json();

        }

        catch {

            data = {};

        }


        if (!response.ok) {

            const message =

                data.detail
                ||
                data.message
                ||
                `Request failed with status ${response.status}`;


            throw new Error(
                message
            );

        }


        return data;

    }

    catch (error) {

        console.error(
            `AEGIS API Error [${endpoint}]:`,
            error
        );

        throw error;

    }

}


/* =========================================================
   BACKEND HEALTH
========================================================= */

async function checkBackendHealth() {

    const statusDot =
        document.getElementById(
            "backendStatusDot"
        );

    const statusText =
        document.getElementById(
            "backendStatusText"
        );


    try {

        await apiRequest(
            "/api/health"
        );


        statusDot.classList.remove(
            "offline"
        );

        statusText.textContent =
            "AEGIS Online";

    }

    catch {

        statusDot.classList.add(
            "offline"
        );

        statusText.textContent =
            "Backend Offline";


        showToast(

            "Backend Offline",

            "Start the FastAPI backend on port 8000.",

            "error"

        );

    }

}


/* =========================================================
   REFRESH ALL DATA
========================================================= */

async function refreshAllData() {

    setLoading(
        true
    );


    try {

        await Promise.allSettled([

            loadAnalyticsOverview(),

            loadRiskTrend(),

            loadSeverityDistribution(),

            loadTopUsers(),

            loadEvents(),

            loadIncidents(),

            loadEventTypes(),

            loadTopSourceIps(),

            loadDetectionStatistics()

        ]);


        await checkBackendHealth();

    }

    finally {

        setLoading(
            false
        );

    }

}


/* =========================================================
   NAVIGATION
========================================================= */

function setupNavigation() {

    const navigationItems =

        document.querySelectorAll(
            ".nav-item"
        );


    navigationItems.forEach(

        item => {

            item.addEventListener(

                "click",

                () => {

                    navigateToSection(

                        item.dataset.section

                    );

                }

            );

        }

    );

}


function navigateToSection(
    sectionName
) {

    state.currentSection =
        sectionName;


    document
        .querySelectorAll(
            ".nav-item"
        )
        .forEach(

            item => {

                item.classList.toggle(

                    "active",

                    item.dataset.section
                    ===
                    sectionName

                );

            }

        );


    document
        .querySelectorAll(
            ".page-section"
        )
        .forEach(

            section => {

                section.classList.remove(
                    "active"
                );

            }

        );


    const targetSection =

        document.getElementById(

            `${sectionName}Section`

        );


    if (targetSection) {

        targetSection.classList.add(
            "active"
        );

    }


    const titles = {

        dashboard:
            "Command Center",

        events:
            "Security Events",

        incidents:
            "Incident Center",

        entities:
            "Entity Intelligence",

        analytics:
            "Analytics",

        simulation:
            "Simulation Lab"

    };


    document.getElementById(
        "pageTitle"
    ).textContent =

        titles[
            sectionName
        ]
        ||
        "AEGIS AI";


    document
        .getElementById(
            "sidebar"
        )
        .classList
        .remove(
            "open"
        );


    if (
        sectionName
        ===
        "events"
    ) {

        loadEvents();

    }


    if (
        sectionName
        ===
        "incidents"
    ) {

        loadIncidents();

    }


    if (
        sectionName
        ===
        "analytics"
    ) {

        loadEventTypes();

        loadTopSourceIps();

        loadDetectionStatistics();

    }

}


/* =========================================================
   MOBILE MENU
========================================================= */

function setupMobileMenu() {

    const menuButton =

        document.getElementById(
            "menuButton"
        );


    menuButton.addEventListener(

        "click",

        () => {

            document
                .getElementById(
                    "sidebar"
                )
                .classList
                .toggle(
                    "open"
                );

        }

    );

}


/* =========================================================
   REFRESH BUTTON
========================================================= */

function setupRefreshButton() {

    const button =

        document.getElementById(
            "refreshButton"
        );


    button.addEventListener(

        "click",

        async () => {

            const icon =

                button.querySelector(
                    "i"
                );


            icon.classList.add(
                "fa-spin"
            );


            await refreshAllData();


            icon.classList.remove(
                "fa-spin"
            );


            showToast(

                "Intelligence Refreshed",

                "AEGIS dashboard data has been updated.",

                "success"

            );

        }

    );

}


/* =========================================================
   ANALYTICS OVERVIEW
========================================================= */

async function loadAnalyticsOverview() {

    try {

        const response =

            await apiRequest(

                "/api/analytics/overview"

            );


        const analytics =

            response.analytics
            ||
            {};


        setText(

            "totalEventsMetric",

            formatNumber(

                analytics.total_events
                ||
                0

            )

        );


        setText(

            "highRiskMetric",

            formatNumber(

                analytics.high_risk_events
                ||
                0

            )

        );


        setText(

            "activeIncidentsMetric",

            formatNumber(

                analytics.active_incidents
                ||
                0

            )

        );


        setText(

            "anomalyRateMetric",

            `${

                Number(

                    analytics.anomaly_rate
                    ||
                    0

                ).toFixed(
                    1
                )

            }%`

        );


        setText(

            "incidentBadge",

            analytics.active_incidents
            ||
            0

        );

    }

    catch (error) {

        console.error(
            "Failed to load analytics overview:",
            error
        );

    }

}


/* =========================================================
   RISK TREND CHART
========================================================= */

async function loadRiskTrend() {

    try {

        const response =

            await apiRequest(

                "/api/analytics/risk-trend?limit=50"

            );


        const data =

            response.data
            ||
            [];


        const labels =

            data.map(

                item =>

                    formatChartTime(

                        item.timestamp

                    )

            );


        const values =

            data.map(

                item =>

                    Number(

                        item.risk_score
                        ||
                        0

                    )

            );


        const canvas =

            document.getElementById(
                "riskTrendChart"
            );


        if (!canvas) {

            return;

        }


        if (
            state.charts.riskTrend
        ) {

            state.charts.riskTrend.destroy();

        }


        const context =

            canvas.getContext(
                "2d"
            );


        const gradient =

            context.createLinearGradient(

                0,
                0,
                0,
                300

            );


        gradient.addColorStop(

            0,

            "rgba(56, 189, 248, 0.30)"

        );


        gradient.addColorStop(

            1,

            "rgba(56, 189, 248, 0.01)"

        );


        state.charts.riskTrend =

            new Chart(

                canvas,

                {

                    type:
                        "line",

                    data: {

                        labels:
                            labels,

                        datasets: [

                            {

                                label:
                                    "Risk Score",

                                data:
                                    values,

                                borderColor:
                                    "#38bdf8",

                                backgroundColor:
                                    gradient,

                                borderWidth:
                                    2,

                                fill:
                                    true,

                                tension:
                                    0.38,

                                pointRadius:
                                    2,

                                pointHoverRadius:
                                    5

                            }

                        ]

                    },

                    options: {

                        responsive:
                            true,

                        maintainAspectRatio:
                            false,

                        interaction: {

                            intersect:
                                false,

                            mode:
                                "index"

                        },

                        plugins: {

                            legend: {

                                display:
                                    false

                            }

                        },

                        scales: {

                            x: {

                                grid: {

                                    display:
                                        false

                                },

                                ticks: {

                                    color:
                                        "#64748b",

                                    maxTicksLimit:
                                        8,

                                    font: {

                                        size:
                                            9

                                    }

                                }

                            },

                            y: {

                                min:
                                    0,

                                max:
                                    100,

                                grid: {

                                    color:
                                        "rgba(148,163,184,0.08)"

                                },

                                ticks: {

                                    color:
                                        "#64748b",

                                    font: {

                                        size:
                                            9

                                    }

                                }

                            }

                        }

                    }

                }

            );

    }

    catch (error) {

        console.error(
            "Risk trend error:",
            error
        );

    }

}


/* =========================================================
   SEVERITY DISTRIBUTION CHART
========================================================= */

async function loadSeverityDistribution() {

    try {

        const response =

            await apiRequest(

                "/api/analytics/severity-distribution"

            );


        const data =

            response.data
            ||
            [];


        const canvas =

            document.getElementById(
                "severityChart"
            );


        if (!canvas) {

            return;

        }


        if (
            state.charts.severity
        ) {

            state.charts.severity.destroy();

        }


        state.charts.severity =

            new Chart(

                canvas,

                {

                    type:
                        "doughnut",

                    data: {

                        labels:

                            data.map(

                                item =>

                                    item.severity

                            ),

                        datasets: [

                            {

                                data:

                                    data.map(

                                        item =>

                                            item.count

                                    ),

                                backgroundColor:

                                    data.map(

                                        item =>

                                            getSeverityColor(

                                                item.severity

                                            )

                                    ),

                                borderColor:
                                    "#0d1422",

                                borderWidth:
                                    4,

                                hoverOffset:
                                    8

                            }

                        ]

                    },

                    options: {

                        responsive:
                            true,

                        maintainAspectRatio:
                            false,

                        cutout:
                            "70%",

                        plugins: {

                            legend: {

                                position:
                                    "bottom",

                                labels: {

                                    color:
                                        "#94a3b8",

                                    usePointStyle:
                                        true,

                                    padding:
                                        16,

                                    font: {

                                        size:
                                            9

                                    }

                                }

                            }

                        }

                    }

                }

            );

    }

    catch (error) {

        console.error(
            "Severity chart error:",
            error
        );

    }

}


/* =========================================================
   EVENT TYPE CHART
========================================================= */

async function loadEventTypes() {

    try {

        const response =

            await apiRequest(

                "/api/analytics/event-types?limit=8"

            );


        const data =

            response.data
            ||
            [];


        const canvas =

            document.getElementById(
                "eventTypesChart"
            );


        if (!canvas) {

            return;

        }


        if (
            state.charts.eventTypes
        ) {

            state.charts.eventTypes.destroy();

        }


        state.charts.eventTypes =

            new Chart(

                canvas,

                {

                    type:
                        "bar",

                    data: {

                        labels:

                            data.map(

                                item =>

                                    formatEventType(

                                        item.event_type

                                    )

                            ),

                        datasets: [

                            {

                                label:
                                    "Events",

                                data:

                                    data.map(

                                        item =>

                                            item.count

                                    ),

                                backgroundColor:
                                    "rgba(99, 102, 241, 0.65)",

                                borderColor:
                                    "#818cf8",

                                borderWidth:
                                    1,

                                borderRadius:
                                    6

                            }

                        ]

                    },

                    options: {

                        responsive:
                            true,

                        maintainAspectRatio:
                            false,

                        plugins: {

                            legend: {

                                display:
                                    false

                            }

                        },

                        scales: {

                            x: {

                                grid: {

                                    display:
                                        false

                                },

                                ticks: {

                                    color:
                                        "#64748b",

                                    font: {

                                        size:
                                            8

                                    }

                                }

                            },

                            y: {

                                beginAtZero:
                                    true,

                                grid: {

                                    color:
                                        "rgba(148,163,184,0.08)"

                                },

                                ticks: {

                                    color:
                                        "#64748b",

                                    precision:
                                        0

                                }

                            }

                        }

                    }

                }

            );

    }

    catch (error) {

        console.error(
            "Event type chart error:",
            error
        );

    }

}


/* =========================================================
   TOP RISKY USERS
========================================================= */

async function loadTopUsers() {

    const container =

        document.getElementById(
            "topUsersList"
        );


    try {

        const response =

            await apiRequest(

                "/api/analytics/top-users?limit=6"

            );


        const users =

            response.data
            ||
            [];


        if (!users.length) {

            container.innerHTML =

                createEmptyState(

                    "fa-user-shield",

                    "No user intelligence available."

                );


            return;

        }


        container.innerHTML =

            users
                .map(

                    (
                        user,
                        index
                    ) => `

                        <div
                            class="ranking-item"
                            onclick="investigateEntityFromDashboard(
                                'users',
                                '${escapeAttribute(user.user_id)}'
                            )"
                            style="cursor:pointer"
                        >

                            <span class="ranking-number">

                                ${String(
                                    index + 1
                                ).padStart(
                                    2,
                                    "0"
                                )}

                            </span>


                            <div class="ranking-info">

                                <strong>

                                    ${escapeHtml(
                                        user.user_id
                                    )}

                                </strong>

                                <small>

                                    ${user.event_count || 0}
                                    events ·
                                    ${user.high_risk_events || 0}
                                    high risk

                                </small>

                            </div>


                            <span
                                class="ranking-score"
                                style="color:
                                    ${getRiskColor(
                                        user.maximum_risk
                                    )}"
                            >

                                ${Math.round(
                                    user.maximum_risk || 0
                                )}

                            </span>

                        </div>

                    `

                )
                .join(
                    ""
                );

    }

    catch {

        container.innerHTML =

            createEmptyState(

                "fa-triangle-exclamation",

                "Unable to load entity rankings."

            );

    }

}


/* =========================================================
   TOP SOURCE IPS
========================================================= */

async function loadTopSourceIps() {

    const container =

        document.getElementById(
            "topIpsList"
        );


    try {

        const response =

            await apiRequest(

                "/api/analytics/top-source-ips?limit=10"

            );


        const ips =

            response.data
            ||
            [];


        if (!ips.length) {

            container.innerHTML =

                createEmptyState(

                    "fa-globe",

                    "No source IP intelligence available."

                );


            return;

        }


        container.innerHTML =

            ips
                .map(

                    (
                        ip,
                        index
                    ) => `

                        <div
                            class="ranking-item"
                            onclick="investigateEntityFromDashboard(
                                'ips',
                                '${escapeAttribute(ip.source_ip)}'
                            )"
                            style="cursor:pointer"
                        >

                            <span class="ranking-number">

                                ${String(
                                    index + 1
                                ).padStart(
                                    2,
                                    "0"
                                )}

                            </span>


                            <div class="ranking-info">

                                <strong class="mono">

                                    ${escapeHtml(
                                        ip.source_ip
                                    )}

                                </strong>

                                <small>

                                    ${ip.event_count || 0}
                                    security events

                                </small>

                            </div>


                            <span
                                class="ranking-score"
                                style="color:
                                    ${getRiskColor(
                                        ip.maximum_risk
                                    )}"
                            >

                                ${Math.round(
                                    ip.maximum_risk || 0
                                )}

                            </span>

                        </div>

                    `

                )
                .join(
                    ""
                );

    }

    catch {

        container.innerHTML =

            createEmptyState(

                "fa-triangle-exclamation",

                "Unable to load source IP analytics."

            );

    }

}


/* =========================================================
   DETECTION ENGINE STATISTICS
========================================================= */

async function loadDetectionStatistics() {

    const container =

        document.getElementById(
            "detectionStats"
        );


    try {

        const response =

            await apiRequest(

                "/api/detections/stats"

            );


        const statistics =

            response.statistics
            ||
            {};


        const ruleEngine =

            statistics.rule_engine
            ||
            {};


        const anomalyEngine =

            statistics.anomaly_engine
            ||
            {};


        container.innerHTML = `

            ${createDetectionEngineCard(

                "Rule Detection Engine",

                ruleEngine.detections || 0,

                ruleEngine.average_score || 0,

                statistics.total_events || 0

            )}


            ${createDetectionEngineCard(

                "AI Anomaly Engine",

                anomalyEngine.detections || 0,

                anomalyEngine.average_score || 0,

                statistics.total_events || 0

            )}

        `;

    }

    catch {

        container.innerHTML =

            createEmptyState(

                "fa-brain",

                "Detection statistics unavailable."

            );

    }

}


function createDetectionEngineCard(

    title,

    detections,

    averageScore,

    totalEvents

) {

    const percentage =

        totalEvents > 0

            ?

            Math.min(

                100,

                (
                    detections
                    /
                    totalEvents
                )
                *
                100

            )

            :

            0;


    return `

        <div class="detection-engine">

            <div class="detection-engine-header">

                <strong>

                    ${escapeHtml(
                        title
                    )}

                </strong>

                <span>

                    ${detections}

                </span>

            </div>


            <div class="progress-track">

                <div
                    class="progress-fill"
                    style="
                        width:
                        ${percentage}%
                    "
                ></div>

            </div>


            <div
                style="
                    margin-top:10px;
                    color:#64748b;
                    font-size:9px;
                "
            >

                Average detection score:
                ${Number(
                    averageScore
                ).toFixed(
                    2
                )}

            </div>

        </div>

    `;

}


/* =========================================================
   SECURITY EVENTS
========================================================= */

async function loadEvents() {

    const tableBody =

        document.getElementById(
            "eventsTableBody"
        );


    try {

        const response =

            await apiRequest(

                "/api/events"

            );


        state.events =

            response.events
            ||
            response.data
            ||
            [];


        renderEvents();

    }

    catch {

        tableBody.innerHTML = `

            <tr>

                <td
                    colspan="7"
                    class="table-empty"
                >

                    Unable to load security events.

                </td>

            </tr>

        `;

    }

}


function renderEvents() {

    const tableBody =

        document.getElementById(
            "eventsTableBody"
        );


    const searchValue =

        document
            .getElementById(
                "eventSearch"
            )
            .value
            .trim()
            .toLowerCase();


    const severity =

        document
            .getElementById(
                "severityFilter"
            )
            .value;


    const minimumRisk =

        Number(

            document
                .getElementById(
                    "minRiskFilter"
                )
                .value
            ||
            0

        );


    const filteredEvents =

        state.events.filter(

            event => {

                const searchableText =

                    [

                        event.event_id,

                        event.event_type,

                        event.user_id,

                        event.source_ip,

                        event.device_id

                    ]
                    .join(
                        " "
                    )
                    .toLowerCase();


                const matchesSearch =

                    !searchValue

                    ||

                    searchableText.includes(
                        searchValue
                    );


                const matchesSeverity =

                    !severity

                    ||

                    String(
                        event.severity
                    ).toLowerCase()
                    ===
                    severity.toLowerCase();


                const matchesRisk =

                    Number(
                        event.risk_score
                        ||
                        0
                    )
                    >=
                    minimumRisk;


                return (

                    matchesSearch
                    &&
                    matchesSeverity
                    &&
                    matchesRisk

                );

            }

        );


    if (!filteredEvents.length) {

        tableBody.innerHTML = `

            <tr>

                <td
                    colspan="7"
                    class="table-empty"
                >

                    No matching security events found.

                </td>

            </tr>

        `;


        return;

    }


    tableBody.innerHTML =

        filteredEvents
            .slice(
                0,
                200
            )
            .map(

                event => `

                    <tr>

                        <td class="mono">

                            ${escapeHtml(
                                event.event_id
                                ||
                                "-"
                            )}

                        </td>


                        <td>

                            ${escapeHtml(

                                formatEventType(

                                    event.event_type

                                )

                            )}

                        </td>


                        <td>

                            ${escapeHtml(
                                event.user_id
                                ||
                                "-"
                            )}

                        </td>


                        <td class="mono">

                            ${escapeHtml(
                                event.source_ip
                                ||
                                "-"
                            )}

                        </td>


                        <td>

                            <strong
                                style="
                                    color:
                                    ${getRiskColor(
                                        event.risk_score
                                    )}
                                "
                            >

                                ${Math.round(
                                    event.risk_score
                                    ||
                                    0
                                )}

                            </strong>

                        </td>


                        <td>

                            ${createSeverityBadge(
                                event.severity
                            )}

                        </td>


                        <td>

                            ${formatDateTime(
                                event.timestamp
                            )}

                        </td>

                    </tr>

                `

            )
            .join(
                ""
            );

}


/* =========================================================
   LIVE EVENT SEARCH
========================================================= */

function setupEventSearch() {

    const searchInput =

        document.getElementById(
            "eventSearch"
        );


    searchInput.addEventListener(

        "input",

        renderEvents

    );

}


/* =========================================================
   INCIDENTS
========================================================= */

async function loadIncidents() {

    try {

        const response =

            await apiRequest(

                "/api/incidents"

            );


        state.incidents =

            response.incidents
            ||
            response.data
            ||
            [];


        renderDashboardIncidents();

        renderIncidentBrowser();


        const activeCount =

            state.incidents.filter(

                incident =>

                    ![
                        "Resolved",
                        "Closed"
                    ]
                    .includes(
                        incident.status
                    )

            )
            .length;


        setText(

            "incidentBadge",

            activeCount

        );

    }

    catch (error) {

        console.error(
            "Incident loading error:",
            error
        );

    }

}


/* =========================================================
   DASHBOARD INCIDENTS
========================================================= */

function renderDashboardIncidents() {

    const container =

        document.getElementById(
            "dashboardIncidentList"
        );


    const incidents =

        state.incidents
            .filter(

                incident =>

                    ![
                        "Resolved",
                        "Closed"
                    ]
                    .includes(
                        incident.status
                    )

            )
            .slice(
                0,
                6
            );


    if (!incidents.length) {

        container.innerHTML =

            createEmptyState(

                "fa-shield-halved",

                "No active incidents detected."

            );


        return;

    }


    container.innerHTML =

        incidents
            .map(

                incident => `

                    <div
                        class="incident-item"
                        onclick="
                            openIncidentFromDashboard(
                                '${escapeAttribute(
                                    incident.incident_id
                                )}'
                            )
                        "
                    >

                        <div class="incident-main">

                            <strong>

                                ${escapeHtml(

                                    incident.title
                                    ||
                                    incident.incident_id

                                )}

                            </strong>


                            <div class="incident-meta">

                                <span>

                                    ${escapeHtml(
                                        incident.incident_id
                                    )}

                                </span>

                                ${createSeverityBadge(
                                    incident.severity
                                )}

                                ${createStatusBadge(
                                    incident.status
                                )}

                            </div>

                        </div>


                        <div
                            class="incident-risk"
                            style="
                                color:
                                ${getRiskColor(

                                    incident.risk_score
                                    ||
                                    incident.max_risk_score

                                )}
                            "
                        >

                            ${Math.round(

                                incident.risk_score
                                ||
                                incident.max_risk_score
                                ||
                                0

                            )}

                        </div>

                    </div>

                `

            )
            .join(
                ""
            );

}


/* =========================================================
   INCIDENT BROWSER
========================================================= */

function renderIncidentBrowser() {

    const container =

        document.getElementById(
            "incidentBrowser"
        );


    if (!state.incidents.length) {

        container.innerHTML =

            createEmptyState(

                "fa-triangle-exclamation",

                "No incidents available. Run correlation after generating events."

            );


        return;

    }


    container.innerHTML =

        state.incidents
            .map(

                incident => `

                    <div
                        class="
                            incident-browser-card

                            ${

                                state.selectedIncidentId
                                ===
                                incident.incident_id

                                ?

                                "active"

                                :

                                ""

                            }
                        "

                        onclick="
                            selectIncident(
                                '${escapeAttribute(
                                    incident.incident_id
                                )}'
                            )
                        "
                    >

                        <h4>

                            ${escapeHtml(

                                incident.title
                                ||
                                incident.incident_id

                            )}

                        </h4>


                        <div class="incident-meta">

                            ${createSeverityBadge(
                                incident.severity
                            )}

                            ${createStatusBadge(
                                incident.status
                            )}

                        </div>


                        <div
                            style="
                                margin-top:10px;
                                color:#64748b;
                                font-size:9px;
                            "
                        >

                            ${escapeHtml(
                                incident.incident_id
                            )}

                        </div>

                    </div>

                `

            )
            .join(
                ""
            );

}


/* =========================================================
   SELECT INCIDENT
========================================================= */

async function selectIncident(
    incidentId
) {

    state.selectedIncidentId =
        incidentId;


    renderIncidentBrowser();


    const detailContainer =

        document.getElementById(
            "incidentDetail"
        );


    detailContainer.innerHTML =

        createEmptyState(

            "fa-spinner fa-spin",

            "Loading incident intelligence..."

        );


    try {

        const response =

            await apiRequest(

                `/api/incidents/${encodeURIComponent(
                    incidentId
                )}`

            );


        const incident =

            response.incident
            ||
            response;


        await renderIncidentDetail(
            incident
        );

    }

    catch (error) {

        detailContainer.innerHTML =

            createEmptyState(

                "fa-triangle-exclamation",

                error.message

            );

    }

}


/* =========================================================
   RENDER INCIDENT DETAIL
========================================================= */

async function renderIncidentDetail(
    incident
) {

    const container =

        document.getElementById(
            "incidentDetail"
        );


    let notes = [];


    try {

        const notesResponse =

            await apiRequest(

                `/api/incidents/${encodeURIComponent(
                    incident.incident_id
                )}/notes`

            );


        notes =

            notesResponse.notes
            ||
            [];

    }

    catch {

        notes = [];

    }


    const riskScore =

        incident.risk_score
        ||
        incident.max_risk_score
        ||
        0;


    container.innerHTML = `

        <div class="detail-header">

            <div>

                <span class="panel-eyebrow">

                    INCIDENT INVESTIGATION

                </span>


                <h2>

                    ${escapeHtml(

                        incident.title
                        ||
                        incident.incident_id

                    )}

                </h2>


                <div class="incident-meta">

                    <span class="mono">

                        ${escapeHtml(
                            incident.incident_id
                        )}

                    </span>

                    ${createSeverityBadge(
                        incident.severity
                    )}

                    ${createStatusBadge(
                        incident.status
                    )}

                </div>

            </div>


            <div
                class="incident-risk"
                style="
                    color:
                    ${getRiskColor(
                        riskScore
                    )};
                    font-size:30px;
                "
            >

                ${Math.round(
                    riskScore
                )}

            </div>

        </div>


        <div class="detail-grid">

            ${createDetailStat(

                "Severity",

                incident.severity
                ||
                "Unknown"

            )}


            ${createDetailStat(

                "Status",

                incident.status
                ||
                "New"

            )}


            ${createDetailStat(

                "Risk Score",

                Math.round(
                    riskScore
                )

            )}


            ${createDetailStat(

                "Event Count",

                incident.event_count
                ||
                (
                    Array.isArray(
                        incident.event_ids
                    )

                        ?

                        incident.event_ids.length

                        :

                        0
                )

            )}


            ${createDetailStat(

                "Primary User",

                incident.user_id
                ||
                incident.primary_user
                ||
                "-"

            )}


            ${createDetailStat(

                "Created",

                formatDateTime(

                    incident.created_at
                    ||
                    incident.timestamp

                )

            )}

        </div>


        <div>

            <span class="panel-eyebrow">

                RESPONSE WORKFLOW

            </span>


            <div class="status-control">

                ${[

                    "New",

                    "Investigating",

                    "Contained",

                    "Resolved",

                    "Closed"

                ]
                .map(

                    status => `

                        <button

                            onclick="
                                updateIncidentStatus(
                                    '${escapeAttribute(
                                        incident.incident_id
                                    )}',
                                    '${status}'
                                )
                            "

                        >

                            ${status}

                        </button>

                    `

                )
                .join(
                    ""
                )}

            </div>

        </div>


        <div class="notes-section">

            <span class="panel-eyebrow">

                INVESTIGATION TIMELINE

            </span>


            <h3>

                Analyst Notes

            </h3>


            <div class="note-form">

                <input

                    id="incidentNoteInput"

                    type="text"

                    maxlength="2000"

                    placeholder="
                        Add investigation note...
                    "

                >


                <button

                    class="primary-button"

                    onclick="
                        addIncidentNote(
                            '${escapeAttribute(
                                incident.incident_id
                            )}'
                        )
                    "

                >

                    <i class="fa-solid fa-plus"></i>

                    Add Note

                </button>

            </div>


            <div>

                ${

                    notes.length

                    ?

                    notes
                        .map(

                            note => `

                                <div class="note-item">

                                    <p>

                                        ${escapeHtml(
                                            note.note
                                        )}

                                    </p>

                                    <small>

                                        ${escapeHtml(
                                            note.analyst
                                            ||
                                            "SOC Analyst"
                                        )}

                                        ·

                                        ${formatDateTime(
                                            note.created_at
                                        )}

                                    </small>

                                </div>

                            `

                        )
                        .join(
                            ""
                        )

                    :

                    `

                        <div class="empty-state">

                            <i class="fa-solid fa-note-sticky"></i>

                            <p>

                                No analyst notes yet.

                            </p>

                        </div>

                    `

                }

            </div>

        </div>

    `;

}


/* =========================================================
   UPDATE INCIDENT STATUS
========================================================= */

async function updateIncidentStatus(

    incidentId,

    status

) {

    setLoading(
        true
    );


    try {

        await apiRequest(

            `/api/incidents/${encodeURIComponent(
                incidentId
            )}/status`,

            {

                method:
                    "PATCH",

                body:
                    JSON.stringify(

                        {
                            status:
                                status
                        }

                    )

            }

        );


        showToast(

            "Incident Updated",

            `Status changed to ${status}.`,

            "success"

        );


        await loadIncidents();

        await loadAnalyticsOverview();

        await selectIncident(
            incidentId
        );

    }

    catch (error) {

        showToast(

            "Status Update Failed",

            error.message,

            "error"

        );

    }

    finally {

        setLoading(
            false
        );

    }

}


/* =========================================================
   ADD INCIDENT NOTE
========================================================= */

async function addIncidentNote(
    incidentId
) {

    const input =

        document.getElementById(
            "incidentNoteInput"
        );


    const note =

        input.value.trim();


    if (!note) {

        showToast(

            "Note Required",

            "Enter an investigation note first.",

            "warning"

        );


        return;

    }


    try {

        await apiRequest(

            `/api/incidents/${encodeURIComponent(
                incidentId
            )}/notes`,

            {

                method:
                    "POST",

                body:
                    JSON.stringify(

                        {

                            note:
                                note,

                            analyst:
                                "SOC Analyst"

                        }

                    )

            }

        );


        showToast(

            "Note Added",

            "Investigation timeline updated.",

            "success"

        );


        await selectIncident(
            incidentId
        );

    }

    catch (error) {

        showToast(

            "Unable to Add Note",

            error.message,

            "error"

        );

    }

}


/* =========================================================
   RUN INCIDENT CORRELATION
========================================================= */

async function correlateIncidents() {

    setLoading(
        true
    );


    try {

        const response =

            await apiRequest(

                "/api/incidents/correlate",

                {

                    method:
                        "POST"

                }

            );


        showToast(

            "Correlation Complete",

            response.message
            ||
            "Security events were analyzed for correlated incidents.",

            "success"

        );


        await loadIncidents();

        await loadAnalyticsOverview();

    }

    catch (error) {

        showToast(

            "Correlation Failed",

            error.message,

            "error"

        );

    }

    finally {

        setLoading(
            false
        );

    }

}


/* =========================================================
   OPEN INCIDENT FROM DASHBOARD
========================================================= */

function openIncidentFromDashboard(
    incidentId
) {

    navigateToSection(
        "incidents"
    );


    selectIncident(
        incidentId
    );

}


/* =========================================================
   ENTITY TYPE SELECTOR
========================================================= */

function setupEntityTypeSelector() {

    const buttons =

        document.querySelectorAll(

            ".entity-type-button"

        );


    buttons.forEach(

        button => {

            button.addEventListener(

                "click",

                () => {

                    buttons.forEach(

                        item =>

                            item.classList.remove(
                                "active"
                            )

                    );


                    button.classList.add(
                        "active"
                    );


                    state.selectedEntityType =

                        button.dataset.entityType;


                    const placeholders = {

                        users:
                            "Enter user ID, for example employee_17...",

                        ips:
                            "Enter IP address, for example 203.0.113.45...",

                        devices:
                            "Enter device ID, for example UNKNOWN-DEVICE..."

                    };


                    document.getElementById(
                        "entitySearchInput"
                    ).placeholder =

                        placeholders[
                            state.selectedEntityType
                        ];

                }

            );

        }

    );

}


/* =========================================================
   SEARCH ENTITY
========================================================= */

async function searchEntity() {

    const input =

        document.getElementById(
            "entitySearchInput"
        );


    const entityId =

        input.value.trim();


    if (!entityId) {

        showToast(

            "Entity Required",

            "Enter an entity identifier to investigate.",

            "warning"

        );


        return;

    }


    const resultContainer =

        document.getElementById(
            "entityResult"
        );


    resultContainer.innerHTML =

        createEmptyState(

            "fa-spinner fa-spin",

            "Building entity intelligence profile..."

        );


    try {

        const response =

            await apiRequest(

                `/api/entities/${state.selectedEntityType}/${encodeURIComponent(
                    entityId
                )}`

            );


        renderEntityProfile(

            response.intelligence

        );

    }

    catch (error) {

        resultContainer.innerHTML =

            createEmptyState(

                "fa-magnifying-glass",

                error.message

            );


        showToast(

            "Entity Not Found",

            error.message,

            "error"

        );

    }

}


/* =========================================================
   DASHBOARD ENTITY INVESTIGATION
========================================================= */

function investigateEntityFromDashboard(

    type,

    entityId

) {

    navigateToSection(
        "entities"
    );


    state.selectedEntityType =
        type;


    document
        .querySelectorAll(
            ".entity-type-button"
        )
        .forEach(

            button => {

                button.classList.toggle(

                    "active",

                    button.dataset.entityType
                    ===
                    type

                );

            }

        );


    document.getElementById(
        "entitySearchInput"
    ).value =

        entityId;


    searchEntity();

}


/* =========================================================
   RENDER ENTITY PROFILE
========================================================= */

function renderEntityProfile(
    intelligence
) {

    const container =

        document.getElementById(
            "entityResult"
        );


    const riskProfile =

        intelligence.risk_profile
        ||
        {};


    const statistics =

        intelligence.statistics
        ||
        {};


    const associations =

        intelligence.associations
        ||
        {};


    const eventTypes =

        intelligence.top_event_types
        ||
        [];


    const recentEvents =

        intelligence.recent_events
        ||
        [];


    container.innerHTML = `

        <div class="entity-profile">


            <article class="panel entity-profile-card">

                <div class="entity-profile-title">

                    <span class="panel-eyebrow">

                        ENTITY PROFILE

                    </span>

                    <h2>

                        ${escapeHtml(
                            intelligence.entity_id
                        )}

                    </h2>

                    <p>

                        ${escapeHtml(

                            formatEventType(

                                intelligence.entity_type

                            )

                        )}

                    </p>

                </div>


                <div class="detail-grid">

                    ${createDetailStat(

                        "Maximum Risk",

                        Math.round(

                            riskProfile.maximum_risk
                            ||
                            0

                        )

                    )}


                    ${createDetailStat(

                        "Average Risk",

                        Number(

                            riskProfile.average_risk
                            ||
                            0

                        ).toFixed(
                            2
                        )

                    )}


                    ${createDetailStat(

                        "Risk Level",

                        riskProfile.risk_level
                        ||
                        getRiskLevel(

                            riskProfile.maximum_risk

                        )

                    )}

                </div>

            </article>


            <article class="panel entity-profile-card">

                <span class="panel-eyebrow">

                    ACTIVITY STATISTICS

                </span>


                <div class="detail-grid">

                    ${createDetailStat(

                        "Total Events",

                        statistics.total_events
                        ||
                        0

                    )}


                    ${createDetailStat(

                        "Anomalies",

                        statistics.anomalies
                        ||
                        0

                    )}


                    ${createDetailStat(

                        "High Risk",

                        statistics.high_risk_events
                        ||
                        0

                    )}

                </div>

            </article>


            <article class="
                panel
                entity-profile-card
            ">

                <span class="panel-eyebrow">

                    ASSOCIATIONS

                </span>


                <div
                    style="
                        margin-top:15px;
                    "
                >

                    ${renderAssociations(
                        associations
                    )}

                </div>

            </article>


            <article class="
                panel
                entity-profile-card
            ">

                <span class="panel-eyebrow">

                    TOP EVENT TYPES

                </span>


                <div
                    class="ranking-list"
                    style="
                        padding:10px 0 0;
                    "
                >

                    ${

                        eventTypes.length

                        ?

                        eventTypes
                            .map(

                                (
                                    item,
                                    index
                                ) => `

                                    <div class="ranking-item">

                                        <span class="ranking-number">

                                            ${index + 1}

                                        </span>

                                        <div class="ranking-info">

                                            <strong>

                                                ${escapeHtml(

                                                    formatEventType(

                                                        item.event_type

                                                    )

                                                )}

                                            </strong>

                                        </div>

                                        <span class="ranking-score">

                                            ${item.count}

                                        </span>

                                    </div>

                                `

                            )
                            .join(
                                ""
                            )

                        :

                        `

                            <div class="empty-state">

                                <p>

                                    No event type data.

                                </p>

                            </div>

                        `

                    }

                </div>

            </article>


            <article class="
                panel
                entity-profile-card
                full-width
            ">

                <span class="panel-eyebrow">

                    RECENT SECURITY ACTIVITY

                </span>


                <div
                    class="table-wrapper"
                    style="
                        margin-top:15px;
                    "
                >

                    <table>

                        <thead>

                            <tr>

                                <th>
                                    Event
                                </th>

                                <th>
                                    Type
                                </th>

                                <th>
                                    Risk
                                </th>

                                <th>
                                    Severity
                                </th>

                                <th>
                                    Time
                                </th>

                            </tr>

                        </thead>


                        <tbody>

                            ${

                                recentEvents.length

                                ?

                                recentEvents
                                    .map(

                                        event => `

                                            <tr>

                                                <td class="mono">

                                                    ${escapeHtml(

                                                        event.event_id
                                                        ||
                                                        "-"

                                                    )}

                                                </td>

                                                <td>

                                                    ${escapeHtml(

                                                        formatEventType(

                                                            event.event_type

                                                        )

                                                    )}

                                                </td>

                                                <td>

                                                    <strong
                                                        style="
                                                            color:
                                                            ${getRiskColor(
                                                                event.risk_score
                                                            )}
                                                        "
                                                    >

                                                        ${Math.round(
                                                            event.risk_score
                                                            ||
                                                            0
                                                        )}

                                                    </strong>

                                                </td>

                                                <td>

                                                    ${createSeverityBadge(
                                                        event.severity
                                                    )}

                                                </td>

                                                <td>

                                                    ${formatDateTime(
                                                        event.timestamp
                                                    )}

                                                </td>

                                            </tr>

                                        `

                                    )
                                    .join(
                                        ""
                                    )

                                :

                                `

                                    <tr>

                                        <td
                                            colspan="5"
                                            class="table-empty"
                                        >

                                            No recent events.

                                        </td>

                                    </tr>

                                `

                            }

                        </tbody>

                    </table>

                </div>

            </article>


        </div>

    `;

}


/* =========================================================
   RENDER ASSOCIATIONS
========================================================= */

function renderAssociations(
    associations
) {

    const groups =

        Object.entries(
            associations
        );


    if (!groups.length) {

        return `

            <div class="empty-state">

                <p>

                    No associations discovered.

                </p>

            </div>

        `;

    }


    return groups
        .map(

            ([

                key,

                values

            ]) => `

                <div
                    style="
                        margin-bottom:16px;
                    "
                >

                    <div
                        style="
                            margin-bottom:8px;
                            color:#64748b;
                            font-size:8px;
                            font-weight:700;
                            letter-spacing:1px;
                            text-transform:uppercase;
                        "
                    >

                        ${escapeHtml(

                            formatEventType(
                                key
                            )

                        )}

                    </div>


                    <div class="association-tags">

                        ${

                            Array.isArray(
                                values
                            )
                            &&
                            values.length

                            ?

                            values
                                .map(

                                    value => `

                                        <span class="association-tag">

                                            ${escapeHtml(
                                                value
                                            )}

                                        </span>

                                    `

                                )
                                .join(
                                    ""
                                )

                            :

                            `

                                <span class="association-tag">

                                    None

                                </span>

                            `

                        }

                    </div>

                </div>

            `

        )
        .join(
            ""
        );

}


/* =========================================================
   SIMULATION SELECTOR
========================================================= */

function setupScenarioSelector() {

    const cards =

        document.querySelectorAll(
            ".scenario-card"
        );


    cards.forEach(

        card => {

            card.addEventListener(

                "click",

                () => {

                    cards.forEach(

                        item =>

                            item.classList.remove(
                                "active"
                            )

                    );


                    card.classList.add(
                        "active"
                    );


                    state.selectedScenario =

                        card.dataset.scenario;


                    const information =

                        scenarioInformation[

                            state.selectedScenario

                        ];


                    setText(

                        "selectedScenarioTitle",

                        information.title

                    );


                    setText(

                        "selectedScenarioDescription",

                        information.description

                    );

                }

            );

        }

    );


    const defaultCard =

        document.querySelector(

            `[data-scenario="${state.selectedScenario}"]`

        );


    if (defaultCard) {

        defaultCard.classList.add(
            "active"
        );

    }

}


/* =========================================================
   RUN SIMULATION
========================================================= */

async function runSimulation() {

    const eventCount =

        Math.max(

            1,

            Math.min(

                100,

                Number(

                    document
                        .getElementById(
                            "simulationEventCount"
                        )
                        .value

                )
                ||
                15

            )

        );


    const button =

        document.getElementById(
            "runSimulationButton"
        );


    const output =

        document.getElementById(
            "simulationOutput"
        );


    button.disabled =
        true;


    button.innerHTML = `

        <i class="
            fa-solid
            fa-spinner
            fa-spin
        "></i>

        Running Analysis...

    `;


    try {

        const response =

            await apiRequest(

                "/api/simulation/generate",

                {

                    method:
                        "POST",

                    body:
                        JSON.stringify(

                            {

                                scenario:
                                    state.selectedScenario,

                                event_count:
                                    eventCount

                            }

                        )

                }

            );


        output.innerHTML = `

            <div class="simulation-result">

                <h3>

                    <i class="
                        fa-solid
                        fa-circle-check
                    "></i>

                    Simulation Complete

                </h3>


                <p>

                    Scenario:

                    <strong>

                        ${escapeHtml(

                            scenarioInformation[
                                state.selectedScenario
                            ].title

                        )}

                    </strong>

                    <br>

                    Generated:

                    <strong>

                        ${

                            response.events_generated
                            ||
                            eventCount

                        }

                        events

                    </strong>

                    <br><br>

                    AEGIS has analyzed and stored the
                    synthetic security telemetry.

                    Run incident correlation to convert
                    related suspicious events into
                    investigation cases.

                </p>


                <div
                    style="
                        display:flex;
                        gap:10px;
                        flex-wrap:wrap;
                        margin-top:16px;
                    "
                >

                    <button
                        class="primary-button"
                        onclick="
                            navigateToSection(
                                'events'
                            )
                        "
                    >

                        View Events

                    </button>


                    <button
                        class="secondary-button"
                        onclick="
                            correlateIncidents()
                        "
                    >

                        Run Correlation

                    </button>

                </div>

            </div>

        `;


        showToast(

            "Simulation Complete",

            `${eventCount} synthetic security events generated.`,

            "success"

        );


        await refreshAllData();

    }

    catch (error) {

        output.innerHTML = `

            <div
                class="simulation-result"
                style="
                    border-color:
                    rgba(239,68,68,0.25);

                    background:
                    rgba(239,68,68,0.05);
                "
            >

                <h3
                    style="
                        color:#fca5a5;
                    "
                >

                    Simulation Failed

                </h3>

                <p>

                    ${escapeHtml(
                        error.message
                    )}

                </p>

            </div>

        `;


        showToast(

            "Simulation Failed",

            error.message,

            "error"

        );

    }

    finally {

        button.disabled =
            false;


        button.innerHTML = `

            <i class="
                fa-solid
                fa-play
            "></i>

            Launch Simulation

        `;

    }

}


/* =========================================================
   CHART DEFAULTS
========================================================= */

function configureChartDefaults() {

    if (
        typeof Chart
        ===
        "undefined"
    ) {

        console.warn(
            "Chart.js is not loaded."
        );


        return;

    }


    Chart.defaults.color =
        "#94a3b8";


    Chart.defaults.font.family =
        "Inter";


    Chart.defaults.borderColor =
        "rgba(148,163,184,0.08)";

}


/* =========================================================
   LOADING OVERLAY
========================================================= */

function setLoading(
    isLoading
) {

    const overlay =

        document.getElementById(
            "loadingOverlay"
        );


    overlay.classList.toggle(

        "active",

        isLoading

    );

}


/* =========================================================
   TOAST NOTIFICATIONS
========================================================= */

function showToast(

    title,

    message,

    type = "success"

) {

    const container =

        document.getElementById(
            "toastContainer"
        );


    const toast =

        document.createElement(
            "div"
        );


    const icons = {

        success:
            "fa-circle-check",

        error:
            "fa-circle-exclamation",

        warning:
            "fa-triangle-exclamation"

    };


    toast.className =

        `toast ${type}`;


    toast.innerHTML = `

        <div class="toast-icon">

            <i class="
                fa-solid
                ${icons[type] || icons.success}
            "></i>

        </div>


        <div class="toast-content">

            <strong>

                ${escapeHtml(
                    title
                )}

            </strong>

            <p>

                ${escapeHtml(
                    message
                )}

            </p>

        </div>

    `;


    container.appendChild(
        toast
    );


    setTimeout(

        () => {

            toast.remove();

        },

        4500

    );

}


/* =========================================================
   UI HELPERS
========================================================= */

function createSeverityBadge(
    severity
) {

    const normalized =

        String(
            severity
            ||
            "Unknown"
        )
        .toLowerCase();


    return `

        <span
            class="
                severity-badge
                severity-${escapeAttribute(
                    normalized
                )}
            "
        >

            ${escapeHtml(
                severity
                ||
                "Unknown"
            )}

        </span>

    `;

}


function createStatusBadge(
    status
) {

    const normalized =

        String(
            status
            ||
            "New"
        )
        .toLowerCase()
        .replace(
            /\s+/g,
            "-"
        );


    return `

        <span
            class="
                status-badge
                status-${escapeAttribute(
                    normalized
                )}
            "
        >

            ${escapeHtml(
                status
                ||
                "New"
            )}

        </span>

    `;

}


function createDetailStat(

    label,

    value

) {

    return `

        <div class="detail-stat">

            <span>

                ${escapeHtml(
                    label
                )}

            </span>

            <strong>

                ${escapeHtml(
                    value
                )}

            </strong>

        </div>

    `;

}


function createEmptyState(

    icon,

    message

) {

    return `

        <div class="empty-state">

            <i class="
                fa-solid
                ${icon}
            "></i>

            <p>

                ${escapeHtml(
                    message
                )}

            </p>

        </div>

    `;

}


/* =========================================================
   FORMATTING HELPERS
========================================================= */

function formatNumber(
    number
) {

    return Number(
        number
        ||
        0
    )
    .toLocaleString();

}


function formatEventType(
    value
) {

    if (!value) {

        return "Unknown";

    }


    return String(
        value
    )
    .replace(
        /_/g,
        " "
    )
    .replace(

        /\b\w/g,

        character =>

            character.toUpperCase()

    );

}


function formatDateTime(
    value
) {

    if (!value) {

        return "-";

    }


    const date =

        new Date(
            value
        );


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return value;

    }


    return date.toLocaleString();

}


function formatChartTime(
    value
) {

    if (!value) {

        return "";

    }


    const date =

        new Date(
            value
        );


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return value;

    }


    return date.toLocaleTimeString(

        [],

        {

            hour:
                "2-digit",

            minute:
                "2-digit"

        }

    );

}


/* =========================================================
   RISK HELPERS
========================================================= */

function getRiskColor(
    riskScore
) {

    const score =

        Number(
            riskScore
            ||
            0
        );


    if (
        score
        >=
        90
    ) {

        return "#f43f5e";

    }


    if (
        score
        >=
        70
    ) {

        return "#ef4444";

    }


    if (
        score
        >=
        40
    ) {

        return "#f59e0b";

    }


    return "#22c55e";

}


function getRiskLevel(
    riskScore
) {

    const score =

        Number(
            riskScore
            ||
            0
        );


    if (
        score
        >=
        90
    ) {

        return "Critical";

    }


    if (
        score
        >=
        70
    ) {

        return "High";

    }


    if (
        score
        >=
        40
    ) {

        return "Medium";

    }


    return "Low";

}


function getSeverityColor(
    severity
) {

    const colors = {

        critical:
            "#f43f5e",

        high:
            "#ef4444",

        medium:
            "#f59e0b",

        low:
            "#22c55e",

        unknown:
            "#64748b"

    };


    return colors[

        String(
            severity
            ||
            "unknown"
        )
        .toLowerCase()

    ]
    ||
    colors.unknown;

}


/* =========================================================
   BASIC SECURITY HELPERS
========================================================= */

function escapeHtml(
    value
) {

    return String(
        value
        ??
        ""
    )
    .replace(
        /&/g,
        "&amp;"
    )
    .replace(
        /</g,
        "&lt;"
    )
    .replace(
        />/g,
        "&gt;"
    )
    .replace(
        /"/g,
        "&quot;"
    )
    .replace(
        /'/g,
        "&#039;"
    );

}


function escapeAttribute(
    value
) {

    return String(
        value
        ??
        ""
    )
    .replace(
        /\\/g,
        "\\\\"
    )
    .replace(
        /'/g,
        "\\'"
    )
    .replace(
        /"/g,
        "&quot;"
    );

}


function setText(

    elementId,

    value

) {

    const element =

        document.getElementById(
            elementId
        );


    if (element) {

        element.textContent =
            value;

    }

}