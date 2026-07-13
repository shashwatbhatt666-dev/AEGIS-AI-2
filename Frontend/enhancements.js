/* =========================================================
   AEGIS AI — 2026 SOC EXPERIENCE LAYER
   -----------------------------------------------------------
   Optional, fully isolated enhancements that sit on top of the
   existing application WITHOUT modifying script.js, its API
   integration, element IDs or DOM contracts.

   Provides:
     - Animated metric counters (MutationObserver based)
     - Command palette (Ctrl / Cmd + K)
     - Notification center (wraps global showToast)
     - Live threat activity feed + animated risk gauge
     - AI Security Copilot (client-side heuristic assistant)

   All hooks are read-only against existing globals
   (navigateToSection, refreshAllData, correlateIncidents,
   showToast, state) and degrade gracefully if unavailable.
========================================================= */

(function () {
    "use strict";


    /* ---------------------------------------------------------
       SMALL UTILITIES
    --------------------------------------------------------- */

    const $ = (id) => document.getElementById(id);

    function safeCall(fnName, ...args) {
        const fn = window[fnName];
        if (typeof fn === "function") {
            try {
                return fn(...args);
            } catch (error) {
                console.log("[v0] enhancement safeCall failed:", fnName, error);
            }
        }
        return undefined;
    }

    function getState() {
        try {
            if (typeof state !== "undefined" && state) {
                return state;
            }
        } catch (_) {
            /* state not in scope yet */
        }
        return null;
    }

    function timeAgo(date) {
        const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
        if (seconds < 60) return "just now";
        const minutes = Math.floor(seconds / 60);
        if (minutes < 60) return `${minutes}m ago`;
        const hours = Math.floor(minutes / 60);
        if (hours < 24) return `${hours}h ago`;
        return `${Math.floor(hours / 24)}d ago`;
    }

    function escapeText(value) {
        const div = document.createElement("div");
        div.textContent = value == null ? "" : String(value);
        return div.innerHTML;
    }


    /* =========================================================
       1. ANIMATED METRIC COUNTERS
    ========================================================= */

    const COUNTER_IDS = [
        "totalEventsMetric",
        "highRiskMetric",
        "activeIncidentsMetric",
        "anomalyRateMetric",
        "incidentBadge"
    ];

    function parseMetric(text) {
        const raw = String(text || "").trim();
        const pct = raw.includes("%");
        const cleaned = raw.replace(/[^0-9.\-]/g, "");
        if (cleaned === "" || cleaned === "-" || cleaned === ".") return null;
        const value = parseFloat(cleaned);
        if (Number.isNaN(value)) return null;
        const decimals = cleaned.includes(".")
            ? (cleaned.split(".")[1] || "").length
            : 0;
        return { value, pct, decimals };
    }

    function formatMetric(value, pct, decimals) {
        if (pct) return `${value.toFixed(decimals || 1)}%`;
        if (decimals > 0) return value.toFixed(decimals);
        return Math.round(value).toLocaleString("en-US");
    }

    function animateCounter(el, from, to, pct, decimals, done) {
        const duration = 900;
        const startTime = performance.now();
        el.classList.add("ax-counting");

        function frame(now) {
            const progress = Math.min((now - startTime) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            const current = from + (to - from) * eased;
            el.textContent = formatMetric(current, pct, decimals);
            if (progress < 1) {
                requestAnimationFrame(frame);
            } else {
                el.textContent = formatMetric(to, pct, decimals);
                el.classList.remove("ax-counting");
                if (typeof done === "function") done();
            }
        }

        requestAnimationFrame(frame);
    }

    function setupCounter(el) {
        const initial = parseMetric(el.textContent);
        el.__axCurrent = initial ? initial.value : 0;

        const observer = new MutationObserver(() => {
            const parsed = parseMetric(el.textContent);
            if (!parsed) return;
            if (parsed.value === el.__axCurrent) return;

            observer.disconnect();
            const from = el.__axCurrent;
            animateCounter(el, from, parsed.value, parsed.pct, parsed.decimals, () => {
                el.__axCurrent = parsed.value;
                observer.observe(el, {
                    childList: true,
                    characterData: true,
                    subtree: true
                });
            });
        });

        observer.observe(el, {
            childList: true,
            characterData: true,
            subtree: true
        });
    }

    function initCounters() {
        COUNTER_IDS.forEach((id) => {
            const el = $(id);
            if (el) setupCounter(el);
        });
    }


    /* =========================================================
       2. NOTIFICATION CENTER (wraps global showToast)
    ========================================================= */

    const notifications = [];
    let unreadCount = 0;

    function renderNotifications() {
        const body = $("axNotificationBody");
        if (!body) return;

        if (!notifications.length) {
            body.innerHTML =
                '<div class="ax-cmdk-empty">No notifications yet.</div>';
            return;
        }

        body.innerHTML = notifications
            .map(
                (n) => `
                <div class="ax-noti ${n.type}">
                    <div class="ax-noti-ico">
                        <i class="fa-solid ${n.icon}"></i>
                    </div>
                    <div class="ax-noti-body">
                        <strong>${escapeText(n.title)}</strong>
                        <p>${escapeText(n.message)}</p>
                        <time>${timeAgo(n.time)}</time>
                    </div>
                </div>`
            )
            .join("");
    }

    function updateNotiBadge() {
        const dot = $("axNotificationDot");
        if (!dot) return;
        dot.classList.toggle("show", unreadCount > 0);
    }

    function addNotification(title, message, type) {
        const iconMap = {
            success: "fa-circle-check",
            error: "fa-circle-exclamation",
            warning: "fa-triangle-exclamation",
            info: "fa-circle-info"
        };
        const safeType = iconMap[type] ? type : "info";
        notifications.unshift({
            title: title || "Notification",
            message: message || "",
            type: safeType,
            icon: iconMap[safeType],
            time: new Date()
        });
        if (notifications.length > 40) notifications.pop();
        unreadCount += 1;
        updateNotiBadge();
        renderNotifications();
    }

    function wrapShowToast() {
        const original = window.showToast;
        window.showToast = function (title, message, type) {
            if (typeof original === "function") {
                original.apply(this, arguments);
            }
            addNotification(title, message, type || "success");
        };
    }

    function toggleDrawer(drawer, open) {
        if (!drawer) return;
        const isOpen =
            open === undefined ? !drawer.classList.contains("open") : open;
        drawer.classList.toggle("open", isOpen);
        return isOpen;
    }

    function initNotifications() {
        wrapShowToast();

        const btn = $("axNotificationBtn");
        const drawer = $("axNotificationDrawer");
        const close = $("axNotificationClose");

        if (btn && drawer) {
            btn.addEventListener("click", () => {
                const opened = toggleDrawer(drawer);
                if (opened) {
                    unreadCount = 0;
                    updateNotiBadge();
                }
            });
        }
        if (close) close.addEventListener("click", () => toggleDrawer(drawer, false));

        addNotification(
            "AEGIS Command Center online",
            "Enterprise SOC experience layer initialized successfully.",
            "success"
        );
    }


    /* =========================================================
       3. COMMAND PALETTE (Ctrl / Cmd + K)
    ========================================================= */

    const commandItems = [
        { group: "Navigate", icon: "fa-grid-2", label: "Command Center", sub: "Dashboard overview", run: () => safeCall("navigateToSection", "dashboard") },
        { group: "Navigate", icon: "fa-wave-square", label: "Security Events", sub: "Event telemetry", run: () => safeCall("navigateToSection", "events") },
        { group: "Navigate", icon: "fa-triangle-exclamation", label: "Incidents", sub: "Case management", run: () => safeCall("navigateToSection", "incidents") },
        { group: "Navigate", icon: "fa-fingerprint", label: "Entity Intelligence", sub: "Investigation graph", run: () => safeCall("navigateToSection", "entities") },
        { group: "Navigate", icon: "fa-chart-line", label: "Analytics", sub: "Detection performance", run: () => safeCall("navigateToSection", "analytics") },
        { group: "Navigate", icon: "fa-flask", label: "Simulation Lab", sub: "Synthetic telemetry", run: () => safeCall("navigateToSection", "simulation") },
        { group: "Actions", icon: "fa-arrows-rotate", label: "Refresh Intelligence", sub: "Reload all dashboard data", run: () => safeCall("refreshAllData") },
        { group: "Actions", icon: "fa-link", label: "Run Correlation", sub: "Correlate events into incidents", run: () => safeCall("correlateIncidents") },
        { group: "Tools", icon: "fa-robot", label: "Open AI Copilot", sub: "Ask the AEGIS assistant", run: () => openCopilot() },
        { group: "Tools", icon: "fa-satellite-dish", label: "Open Live Threat Feed", sub: "Streaming detections", run: () => openThreatFeed() },
        { group: "Tools", icon: "fa-bell", label: "Open Notifications", sub: "Recent alerts", run: () => { unreadCount = 0; updateNotiBadge(); toggleDrawer($("axNotificationDrawer"), true); } }
    ];

    let cmdActiveIndex = 0;
    let cmdFiltered = commandItems.slice();

    function renderCommandList(query) {
        const list = $("axCommandList");
        if (!list) return;

        const q = (query || "").trim().toLowerCase();
        cmdFiltered = commandItems.filter(
            (item) =>
                !q ||
                item.label.toLowerCase().includes(q) ||
                item.sub.toLowerCase().includes(q) ||
                item.group.toLowerCase().includes(q)
        );

        if (!cmdFiltered.length) {
            list.innerHTML =
                '<div class="ax-cmdk-empty">No matching commands.</div>';
            return;
        }

        cmdActiveIndex = Math.min(cmdActiveIndex, cmdFiltered.length - 1);

        let html = "";
        let lastGroup = null;
        cmdFiltered.forEach((item, index) => {
            if (item.group !== lastGroup) {
                html += `<div class="ax-cmdk-group">${item.group}</div>`;
                lastGroup = item.group;
            }
            html += `
                <button
                    class="ax-cmdk-item ${index === cmdActiveIndex ? "active" : ""}"
                    data-index="${index}"
                    type="button"
                >
                    <i class="fa-solid ${item.icon}"></i>
                    <span class="ax-cmdk-label">${item.label}</span>
                    <span class="ax-cmdk-sub">${item.sub}</span>
                </button>`;
        });
        list.innerHTML = html;
    }

    function openCommandPalette() {
        const overlay = $("axCommandPalette");
        const input = $("axCommandInput");
        if (!overlay) return;
        overlay.classList.add("open");
        cmdActiveIndex = 0;
        if (input) {
            input.value = "";
            renderCommandList("");
            setTimeout(() => input.focus(), 40);
        }
    }

    function closeCommandPalette() {
        const overlay = $("axCommandPalette");
        if (overlay) overlay.classList.remove("open");
    }

    function runCommand(index) {
        const item = cmdFiltered[index];
        if (!item) return;
        closeCommandPalette();
        item.run();
    }

    function initCommandPalette() {
        const overlay = $("axCommandPalette");
        const input = $("axCommandInput");
        const list = $("axCommandList");
        const hint = $("axCommandHint");

        if (hint) hint.addEventListener("click", openCommandPalette);

        document.addEventListener("keydown", (event) => {
            const key = event.key.toLowerCase();
            if ((event.metaKey || event.ctrlKey) && key === "k") {
                event.preventDefault();
                const overlayEl = $("axCommandPalette");
                if (overlayEl && overlayEl.classList.contains("open")) {
                    closeCommandPalette();
                } else {
                    openCommandPalette();
                }
                return;
            }
            if (key === "escape") {
                closeCommandPalette();
            }
        });

        if (overlay) {
            overlay.addEventListener("click", (event) => {
                if (event.target === overlay) closeCommandPalette();
            });
        }

        if (input) {
            input.addEventListener("input", (event) => {
                cmdActiveIndex = 0;
                renderCommandList(event.target.value);
            });

            input.addEventListener("keydown", (event) => {
                if (event.key === "ArrowDown") {
                    event.preventDefault();
                    cmdActiveIndex = Math.min(cmdActiveIndex + 1, cmdFiltered.length - 1);
                    renderCommandList(input.value);
                } else if (event.key === "ArrowUp") {
                    event.preventDefault();
                    cmdActiveIndex = Math.max(cmdActiveIndex - 1, 0);
                    renderCommandList(input.value);
                } else if (event.key === "Enter") {
                    event.preventDefault();
                    runCommand(cmdActiveIndex);
                }
            });
        }

        if (list) {
            list.addEventListener("click", (event) => {
                const btn = event.target.closest(".ax-cmdk-item");
                if (!btn) return;
                runCommand(Number(btn.dataset.index));
            });
        }
    }


    /* =========================================================
       4. LIVE THREAT ACTIVITY FEED + RISK GAUGE
    ========================================================= */

    let lastSeenSignature = null;
    let feedUnseen = 0;

    function severityClass(severity, riskScore) {
        const level = String(
            severity || safeCall("getRiskLevel", riskScore) || "Low"
        ).toLowerCase();
        if (level.includes("crit")) return "critical";
        if (level.includes("high")) return "high";
        if (level.includes("med")) return "medium";
        return "low";
    }

    function formatType(type) {
        return String(type || "Security Event")
            .replace(/_/g, " ")
            .replace(/\b\w/g, (c) => c.toUpperCase());
    }

    function renderThreatFeed() {
        const body = $("axThreatFeedBody");
        const state = getState();
        if (!body) return;

        const events = state && Array.isArray(state.events) ? state.events : [];

        if (!events.length) {
            body.innerHTML =
                '<div class="ax-cmdk-empty">Awaiting live telemetry. Run a simulation to stream detections.</div>';
            return;
        }

        const recent = events.slice(0, 25);
        body.innerHTML = recent
            .map((event) => {
                const cls = severityClass(event.severity, event.risk_score);
                const risk = Math.round(Number(event.risk_score || 0));
                const when = event.timestamp
                    ? new Date(event.timestamp)
                    : new Date();
                return `
                    <div class="ax-feed-item ${cls}">
                        <span class="ax-feed-dot"></span>
                        <div class="ax-feed-body">
                            <strong>${escapeText(formatType(event.event_type))}</strong>
                            <p>
                                ${escapeText(event.user_id || "unknown user")}
                                &middot;
                                ${escapeText(event.source_ip || "no ip")}
                                &middot; risk ${risk}
                            </p>
                            <time>${escapeText(event.severity || safeCall("getRiskLevel", event.risk_score) || "Low")} &middot; ${timeAgo(when)}</time>
                        </div>
                    </div>`;
            })
            .join("");
    }

    function updateRiskGauge() {
        const state = getState();
        const gauge = $("axFeedGauge");
        const value = $("axFeedGaugeValue");
        const label = $("axFeedGaugeLabel");
        if (!gauge || !value) return;

        const events = state && Array.isArray(state.events) ? state.events : [];
        let score = 0;
        if (events.length) {
            const recent = events.slice(0, 20);
            const total = recent.reduce(
                (sum, e) => sum + Number(e.risk_score || 0),
                0
            );
            score = Math.round(total / recent.length);
        }

        gauge.style.setProperty("--val", score);
        let color = "var(--success)";
        let text = "Low exposure";
        if (score >= 70) {
            color = "var(--danger)";
            text = "Critical exposure";
        } else if (score >= 40) {
            color = "var(--warning)";
            text = "Elevated exposure";
        } else if (score > 0) {
            text = "Nominal exposure";
        } else {
            text = "Analyzing...";
        }
        gauge.style.setProperty("--ax-gauge-color", color);
        value.textContent = score;
        if (label) label.textContent = text;
    }

    function feedSignature() {
        const state = getState();
        const events = state && Array.isArray(state.events) ? state.events : [];
        if (!events.length) return "empty";
        const top = events[0] || {};
        return `${events.length}:${top.event_id || top.timestamp || ""}`;
    }

    function updateFeedBadge() {
        const badge = $("axThreatFeedBadge");
        if (!badge) return;
        badge.textContent = feedUnseen > 99 ? "99+" : String(feedUnseen);
        badge.style.display = feedUnseen > 0 ? "grid" : "none";
    }

    function pollThreatFeed() {
        const signature = feedSignature();
        if (signature !== lastSeenSignature) {
            const drawer = $("axThreatFeed");
            const drawerOpen = drawer && drawer.classList.contains("open");
            if (lastSeenSignature !== null && !drawerOpen) {
                feedUnseen += 1;
                updateFeedBadge();
            }
            lastSeenSignature = signature;
            renderThreatFeed();
            updateRiskGauge();
        }
    }

    function openThreatFeed() {
        renderThreatFeed();
        updateRiskGauge();
        feedUnseen = 0;
        updateFeedBadge();
        toggleDrawer($("axThreatFeed"), true);
    }

    function initThreatFeed() {
        const btn = $("axThreatFeedBtn");
        const close = $("axThreatFeedClose");
        if (btn) btn.addEventListener("click", openThreatFeed);
        if (close)
            close.addEventListener("click", () =>
                toggleDrawer($("axThreatFeed"), false)
            );

        updateFeedBadge();
        setInterval(pollThreatFeed, 2500);
        setTimeout(pollThreatFeed, 1500);
    }


    /* =========================================================
       5. AI SECURITY COPILOT (client-side heuristic assistant)
    ========================================================= */

    function metricText(id, fallback) {
        const el = $(id);
        return el ? el.textContent.trim() : fallback;
    }

    function buildCopilotAnswer(question) {
        const q = question.toLowerCase();
        const total = metricText("totalEventsMetric", "0");
        const highRisk = metricText("highRiskMetric", "0");
        const incidents = metricText("activeIncidentsMetric", "0");
        const anomaly = metricText("anomalyRateMetric", "0%");

        if (q.includes("posture") || q.includes("risk") || q.includes("status")) {
            return `Current security posture: <strong>${total}</strong> analyzed events, <strong>${highRisk}</strong> high-risk detections and <strong>${incidents}</strong> active incidents. The behavioral anomaly rate is <strong>${anomaly}</strong>. Open the Live Threat Feed for the aggregate risk gauge.`;
        }
        if (q.includes("incident")) {
            return `There are currently <strong>${incidents}</strong> active incidents. Head to the Incidents section to investigate correlated threats, update status and add analyst notes. You can also run correlation from the command palette.`;
        }
        if (q.includes("anomaly") || q.includes("ml") || q.includes("model")) {
            return `The ML anomaly detector reports an anomaly rate of <strong>${anomaly}</strong>. This reflects the share of events flagged as behavioral outliers by the unsupervised model, layered on top of the rule-based and correlation engines.`;
        }
        if (q.includes("event")) {
            return `AEGIS has analyzed <strong>${total}</strong> security events, of which <strong>${highRisk}</strong> are high risk. Use the Security Events section to search, filter by severity and inspect individual telemetry.`;
        }
        if (q.includes("simulat")) {
            return `You can generate synthetic telemetry in the Simulation Lab. The <strong>Account Compromise</strong> scenario is recommended for demonstrating multi-stage detection, risk scoring and incident correlation.`;
        }
        if (q.includes("hello") || q.includes("hi") || q.includes("help")) {
            return `Hi, I'm the AEGIS Copilot. I can summarize your live security posture, active incidents, anomaly rate and events. Try one of the suggestions below, or ask about a specific section.`;
        }
        return `I can help you interpret your live SOC data. Right now: <strong>${total}</strong> events, <strong>${highRisk}</strong> high-risk, <strong>${incidents}</strong> incidents, anomaly rate <strong>${anomaly}</strong>. Ask about posture, incidents, anomalies or the simulation lab.`;
    }

    function appendMessage(role, html) {
        const body = $("axCopilotBody");
        if (!body) return;
        const msg = document.createElement("div");
        msg.className = `ax-msg ${role}`;
        msg.innerHTML = html;
        body.appendChild(msg);
        body.scrollTop = body.scrollHeight;
    }

    function showTyping() {
        const body = $("axCopilotBody");
        if (!body) return null;
        const typing = document.createElement("div");
        typing.className = "ax-msg-typing";
        typing.innerHTML = "<span></span><span></span><span></span>";
        body.appendChild(typing);
        body.scrollTop = body.scrollHeight;
        return typing;
    }

    function askCopilot(question) {
        if (!question) return;
        appendMessage("user", escapeText(question));
        const typing = showTyping();
        setTimeout(() => {
            if (typing) typing.remove();
            appendMessage("bot", buildCopilotAnswer(question));
        }, 650);
    }

    let copilotGreeted = false;

    function openCopilot() {
        const panel = $("axCopilot");
        if (!panel) return;
        panel.classList.add("open");
        if (!copilotGreeted) {
            appendMessage(
                "bot",
                "Welcome to the <strong>AEGIS Copilot</strong>. I analyze your live SOC telemetry client-side. Ask me about your security posture, incidents or anomaly rate."
            );
            copilotGreeted = true;
        }
        const input = $("axCopilotInput");
        if (input) setTimeout(() => input.focus(), 60);
    }

    function initCopilot() {
        const btn = $("axCopilotBtn");
        const close = $("axCopilotClose");
        const form = $("axCopilotForm");
        const input = $("axCopilotInput");
        const suggest = $("axCopilotSuggest");

        if (btn)
            btn.addEventListener("click", () => {
                const panel = $("axCopilot");
                if (panel && panel.classList.contains("open")) {
                    panel.classList.remove("open");
                } else {
                    openCopilot();
                }
            });

        if (close)
            close.addEventListener("click", () =>
                $("axCopilot").classList.remove("open")
            );

        if (input) {
            input.addEventListener("compositionstart", () => {
                input.__axComposing = true;
            });
            input.addEventListener("compositionend", () => {
                input.__axComposing = false;
            });
            input.addEventListener("keydown", (event) => {
                if (
                    event.key === "Enter" &&
                    (input.__axComposing || event.keyCode === 229)
                ) {
                    event.stopPropagation();
                }
            });
        }

        if (form) {
            form.addEventListener("submit", (event) => {
                event.preventDefault();
                if (input && input.__axComposing) return;
                const value = input ? input.value.trim() : "";
                if (!value) return;
                input.value = "";
                askCopilot(value);
            });
        }

        if (suggest) {
            suggest.addEventListener("click", (event) => {
                const chip = event.target.closest(".ax-chip");
                if (!chip) return;
                askCopilot(chip.dataset.ask);
            });
        }
    }


    /* =========================================================
       BOOTSTRAP
    ========================================================= */

    function boot() {
        initCounters();
        initNotifications();
        initCommandPalette();
        initThreatFeed();
        initCopilot();
        console.log("[v0] AEGIS 2026 SOC experience layer ready");
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot);
    } else {
        boot();
    }
})();
