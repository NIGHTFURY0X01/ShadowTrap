"use strict";

/* ============================================
   CONFIG
============================================ */

const API_BASE =
    window.location.protocol.startsWith("http")
        ? window.location.origin
        : "http://127.0.0.1:8000";

const REFRESH_INTERVAL = 10000;

let refreshTimer = null;


/* ============================================
   HELPERS
============================================ */

const byId = (id) => document.getElementById(id);

const setText = (id, value) => {
    const element = byId(id);

    if (element) {
        element.textContent = value ?? "—";
    }
};

const number = (value) =>
    new Intl.NumberFormat().format(value ?? 0);


function apiHeaders() {
    const key = sessionStorage.getItem("shadowtrap-api-key");

    return key
        ? { "X-API-Key": key }
        : {};
}


async function request(path) {
    const response = await fetch(
        `${API_BASE}${path}`,
        {
            headers: apiHeaders()
        }
    );

    if (!response.ok) {
        const payload =
            await response
                .json()
                .catch(() => ({}));

        throw new Error(
            payload.detail ||
            `Request failed (${response.status})`
        );
    }

    return response.json();
}


function setApiStatus(online, label) {
    const status = byId("api-status");

    if (!status) {
        return;
    }

    status.classList.toggle("online", online);
    status.classList.toggle("offline", !online);

    const span = status.querySelector("span");

    if (span) {
        span.textContent = label;
    }
}


/* ============================================
   HTML ESCAPING
============================================ */

function escapeHTML(value) {
    const div = document.createElement("div");

    div.textContent = String(value ?? "");

    return div.innerHTML;
}


/* ============================================
   TIME
============================================ */

function formatTime(timestamp) {
    if (!timestamp) {
        return "—";
    }

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return timestamp;
    }

    return date.toLocaleString();
}


/* ============================================
   SERVICE BARS
============================================ */

function renderServiceBars(services, total) {
    const container = byId("service-bars");

    if (!container) {
        return;
    }

    container.replaceChildren();

    const entries =
        Object.entries(services || {});

    if (!entries.length) {
        const empty =
            document.createElement("p");

        empty.className = "empty-state";
        empty.textContent =
            "No events collected yet.";

        container.append(empty);

        return;
    }

    entries
        .sort((a, b) => b[1] - a[1])
        .forEach(([service, count]) => {

            const card =
                document.createElement("article");

            card.className = "service-bar";


            const header =
                document.createElement("header");


            const name =
                document.createElement("span");

            name.textContent = service;


            const value =
                document.createElement("span");

            value.textContent = number(count);


            header.append(name, value);


            const bar =
                document.createElement("div");

            bar.className = "bar";


            const fill =
                document.createElement("span");

            fill.style.width =
                `${Math.max(
                    3,
                    (count / Math.max(total, 1)) * 100
                )}%`;


            bar.append(fill);

            card.append(header, bar);

            container.append(card);
        });
}


/* ============================================
   GLOBAL STATS
============================================ */

async function loadStats() {
    try {

        const [
            health,
            stats
        ] = await Promise.all([
            request("/api/health"),
            request("/api/stats")
        ]);


        setApiStatus(
            health.status === "ok",
            "API online"
        );


        setText(
            "total-attacks",
            number(stats.total_attacks)
        );


        setText(
            "unique-ips",
            number(stats.unique_ips)
        );


        setText(
            "ssh-attacks",
            number(stats.ssh_attacks)
        );


        setText(
            "http-attacks",
            number(stats.http_attacks)
        );


        setText(
            "authentication-attempts",
            number(stats.authentication_attempts)
        );


        setText(
            "suspicious-requests",
            number(stats.suspicious_requests)
        );


        renderServiceBars(
            stats.services,
            stats.total_attacks
        );


        setText(
            "last-updated",
            `Updated ${new Date().toLocaleTimeString()}`
        );


        return stats;

    } catch (error) {

        setApiStatus(
            false,
            "API unavailable"
        );

        console.error(
            "Failed to load stats:",
            error
        );

        throw error;
    }
}


/* ============================================
   TABLE CELL
============================================ */

function cell(text, className = "") {
    const element =
        document.createElement("td");

    if (className) {
        element.className = className;
    }

    element.textContent =
        text ?? "—";

    return element;
}


/* ============================================
   RECENT ATTACKS
============================================ */

function renderAttacks(attacks) {

    const body =
        byId("attacks-table");

    if (!body) {
        return;
    }

    body.replaceChildren();


    const attackList =
        Array.isArray(attacks)
            ? attacks
            : [];


    setText(
        "attack-count",
        `${number(attackList.length)} shown`
    );


    if (!attackList.length) {

        const row =
            document.createElement("tr");


        const empty =
            cell(
                "No attacks recorded.",
                "empty-state"
            );


        empty.colSpan = 6;

        row.append(empty);

        body.append(row);

        return;
    }


    attackList.forEach((attack) => {

        const row =
            document.createElement("tr");


        row.append(
            cell(
                formatTime(attack.timestamp)
            )
        );


        row.append(
            cell(
                attack.source_ip
            )
        );


        row.append(
            cell(
                attack.service,
                "service"
            )
        );


        const eventCell =
            document.createElement("td");


        const chip =
            document.createElement("span");


        chip.className =
            "event-chip";


        chip.textContent =
            attack.event ?? "—";


        eventCell.append(chip);

        row.append(eventCell);


        row.append(
            cell(
                attack.metadata?.path ||
                attack.username ||
                "—"
            )
        );


        const action =
            document.createElement("td");


        const button =
            document.createElement("button");


        button.type = "button";

        button.className =
            "investigate-link";

        button.textContent =
            "Investigate";


        button.addEventListener(
            "click",
            () => {

                const ip =
                    attack.source_ip;

                const input =
                    byId("ip-input");

                if (input) {
                    input.value = ip || "";
                }

                if (ip) {
                    investigate(ip);
                }
            }
        );


        action.append(button);

        row.append(action);

        body.append(row);
    });
}


async function loadAttacks() {
    const data =
        await request(
            "/api/attacks?limit=25"
        );

    renderAttacks(
        data.attacks || []
    );

    return data;
}


/* ============================================
   HTTP ATTACK ANALYSIS
============================================ */

async function loadHTTPAnalysis() {

    const input =
        byId("ip-input");

    const container =
        byId("http-analysis");


    if (!input || !container) {
        return;
    }


    const ip =
        input.value.trim();


    if (!ip) {

        container.innerHTML = `
            <div class="empty-state">
                Please enter an IP address.
            </div>
        `;

        return;
    }


    container.innerHTML = `
        <div class="empty-state">
            Loading HTTP intelligence...
        </div>
    `;


    try {

        const data =
            await request(
                `/api/http/${encodeURIComponent(ip)}`
            );


        renderHTTPAnalysis(data);


    } catch (error) {

        console.error(
            "Failed to load HTTP analysis:",
            error
        );


        container.innerHTML = `
            <div class="empty-state">
                ${escapeHTML(error.message)}
            </div>
        `;
    }
}


/* ============================================
   RENDER HTTP ANALYSIS
============================================ */

function renderHTTPAnalysis(result) {

    const container =
        byId("http-analysis");

    if (!container) {
        return;
    }


    const scanner =
        Boolean(
            result.scanner_detected
        );


    const bruteForce =
        Boolean(
            result.brute_force_detected
        );


    const severity =
        String(
            result.severity || "-"
        );


    const severityClass =
        `severity-${severity.toLowerCase()}`;


    container.innerHTML = `

        <div class="http-grid">

            <div class="http-stat">
                <span class="http-stat-label">
                    HTTP Requests
                </span>

                <span class="http-stat-value">
                    ${result.http_requests ?? 0}
                </span>
            </div>


            <div class="http-stat">
                <span class="http-stat-label">
                    Authentication Attempts
                </span>

                <span class="http-stat-value">
                    ${result.authentication_attempts ?? 0}
                </span>
            </div>


            <div class="http-stat">
                <span class="http-stat-label">
                    Unique Paths
                </span>

                <span class="http-stat-value">
                    ${result.unique_paths ?? 0}
                </span>
            </div>


            <div class="http-stat">
                <span class="http-stat-label">
                    Suspicious Paths
                </span>

                <span class="http-stat-value">
                    ${result.suspicious_paths ?? 0}
                </span>
            </div>

        </div>


        <div class="detection-grid">

            <div class="detection">

                <span class="detection-label">
                    Scanner Detection
                </span>

                <span class="
                    badge
                    ${scanner
                        ? "badge-danger"
                        : "badge-safe"}
                ">
                    ${scanner
                        ? "DETECTED"
                        : "NOT DETECTED"}
                </span>

            </div>


            <div class="detection">

                <span class="detection-label">
                    Brute Force Detection
                </span>

                <span class="
                    badge
                    ${bruteForce
                        ? "badge-danger"
                        : "badge-safe"}
                ">
                    ${bruteForce
                        ? "DETECTED"
                        : "NOT DETECTED"}
                </span>

            </div>

        </div>


        <div class="risk-section">

            <div class="risk-box">

                <span class="risk-label">
                    Risk Score
                </span>

                <span class="risk-value">
                    ${result.risk_score ?? 0}/100
                </span>

            </div>


            <div class="risk-box">

                <span class="risk-label">
                    Severity
                </span>

                <span class="
                    risk-value
                    ${severityClass}
                ">
                    ${escapeHTML(severity)}
                </span>

            </div>


            <div class="risk-box">

                <span class="risk-label">
                    Classification
                </span>

                <span class="risk-value">
                    ${escapeHTML(
                        result.classification || "-"
                    )}
                </span>

            </div>

        </div>
    `;
}


/* ============================================
   KEY / VALUE LIST
============================================ */

function keyValues(containerId, entries) {

    const list =
        byId(containerId);

    if (!list) {
        return;
    }

    list.replaceChildren();


    entries.forEach(
        ([label, value]) => {

            const term =
                document.createElement("dt");

            term.textContent =
                label;


            const detail =
                document.createElement("dd");

            detail.textContent =
                value ?? "—";


            list.append(
                term,
                detail
            );
        }
    );
}


/* ============================================
   INVESTIGATION TIMELINE
============================================ */

function renderTimeline(events) {

    const timeline =
        byId("timeline");

    if (!timeline) {
        return;
    }

    timeline.replaceChildren();


    const eventList =
        Array.isArray(events)
            ? events
            : [];


    eventList.forEach((event) => {

        const item =
            document.createElement("li");


        const time =
            document.createElement("time");

        time.textContent =
            formatTime(event.timestamp);


        const type =
            document.createElement("span");

        type.className =
            "event-type";


        type.textContent =
            `${String(
                event.service || "-"
            ).toUpperCase()} · ${
                event.event || "-"
            }`;


        const detail =
            document.createElement("span");

        detail.className =
            "event-detail";


        detail.textContent =
            [
                event.method,
                event.path,
                event.username
                    ? `user: ${event.username}`
                    : ""
            ]
                .filter(Boolean)
                .join(" ")
            || "Connection activity";


        item.append(
            time,
            type,
            detail
        );


        timeline.append(item);
    });
}


/* ============================================
   INVESTIGATION
============================================ */

async function investigate(ip) {

    if (!ip) {
        return;
    }


    const message =
        byId("investigation-message");


    if (message) {

        message.classList.remove("error");

        message.textContent =
            "Loading intelligence…";
    }


    try {

        const [
            result,
            timeline
        ] = await Promise.all([

            request(
                `/api/investigate/${encodeURIComponent(ip)}`
            ),

            request(
                `/api/timeline/${encodeURIComponent(ip)}?limit=100`
            )

        ]);


        const resultContainer =
            byId("investigation-result");


        if (resultContainer) {
            resultContainer.hidden = false;
        }


        setText(
            "investigation-risk",
            result.risk_score
        );


        setText(
            "investigation-severity",
            result.severity
        );


        setText(
            "investigation-classification",
            result.classification
        );


        /* Evidence */

        const evidence =
            byId("evidence-list");


        if (evidence) {

            evidence.replaceChildren();


            const values =
                result.evidence?.length
                    ? result.evidence
                    : [
                        "No high-confidence indicators beyond collected activity."
                    ];


            values.forEach((value) => {

                const item =
                    document.createElement("li");

                item.textContent =
                    value;

                evidence.append(item);
            });
        }


        /* HTTP intelligence */

        const http =
            result.http || {};


        keyValues(
            "http-intelligence",
            [
                [
                    "Requests",
                    http.http_requests
                ],

                [
                    "Auth attempts",
                    http.authentication_attempts
                ],

                [
                    "Unique paths",
                    http.unique_paths
                ],

                [
                    "Suspicious paths",
                    http.suspicious_paths
                ],

                [
                    "Scanner",
                    http.scanner_detected
                        ? "DETECTED"
                        : "Not detected"
                ],

                [
                    "Brute force",
                    http.brute_force_detected
                        ? "DETECTED"
                        : "Not detected"
                ]
            ]
        );


        /* Campaign intelligence */

        const campaign =
            result.campaign || {};


        const credentials =
            result.credentials || {};


        keyValues(
            "campaign-intelligence",
            [
                [
                    "Campaign",
                    campaign.pattern || "—"
                ],

                [
                    "Confidence",
                    campaign.confidence
                        ? `${campaign.confidence}%`
                        : "—"
                ],

                [
                    "Username spray",
                    credentials.username_spray
                        ? "DETECTED"
                        : "Not detected"
                ],

                [
                    "Password reuse",
                    credentials.password_reuse
                        ? "DETECTED"
                        : "Not detected"
                ],

                [
                    "Services",
                    result.general?.unique_services
                ]
            ]
        );


        /* Timeline */

        renderTimeline(
            timeline.events || []
        );


        setText(
            "timeline-count",
            `${number(
                timeline.count || 0
            )} events`
        );


        if (message) {

            message.textContent =
                `Investigation complete for ${result.source_ip}.`;
        }


    } catch (error) {

        const resultContainer =
            byId("investigation-result");


        if (resultContainer) {
            resultContainer.hidden = true;
        }


        if (message) {

            message.classList.add("error");

            message.textContent =
                error.message;
        }


        console.error(
            "Investigation failed:",
            error
        );
    }
}


/* ============================================
   DASHBOARD REFRESH
============================================ */

async function refreshDashboard() {

    try {

        await Promise.all([
            loadStats(),
            loadAttacks()
        ]);

    } catch (error) {

        setApiStatus(
            false,
            "API unavailable"
        );


        console.error(
            "Dashboard refresh failed:",
            error
        );
    }
}


/* ============================================
   AUTO REFRESH
============================================ */

function configureRefreshTimer() {

    window.clearInterval(
        refreshTimer
    );


    const checkbox =
        byId("auto-refresh");


    if (
        checkbox &&
        checkbox.checked
    ) {

        refreshTimer =
            window.setInterval(
                refreshDashboard,
                REFRESH_INTERVAL
            );
    }
}


/* ============================================
   INITIALIZATION
============================================ */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        /* API key */

        const apiKey =
            byId("api-key");


        if (apiKey) {

            apiKey.value =
                sessionStorage.getItem(
                    "shadowtrap-api-key"
                ) || "";
        }


        /* Save API key */

        const saveApiKey =
            byId("save-api-key");


        if (saveApiKey) {

            saveApiKey.addEventListener(
                "click",
                () => {

                    const key =
                        apiKey?.value.trim() || "";


                    if (key) {

                        sessionStorage.setItem(
                            "shadowtrap-api-key",
                            key
                        );

                    } else {

                        sessionStorage.removeItem(
                            "shadowtrap-api-key"
                        );
                    }


                    refreshDashboard();
                }
            );
        }


        /* Refresh button */

        const refreshButton =
            byId("refresh-button");


        if (refreshButton) {

            refreshButton.addEventListener(
                "click",
                refreshDashboard
            );
        }


        /* Auto refresh */

        const autoRefresh =
            byId("auto-refresh");


        if (autoRefresh) {

            autoRefresh.addEventListener(
                "change",
                configureRefreshTimer
            );
        }


        /* Investigation form */

        const investigationForm =
            byId("investigation-form");


        if (investigationForm) {

            investigationForm.addEventListener(
                "submit",
                (event) => {

                    event.preventDefault();


                    const input =
                        byId("ip-input");


                    const ip =
                        input?.value.trim() || "";


                    investigate(ip);
                }
            );
        }


        /* HTTP analysis Enter key */

        const ipInput =
            byId("ip-input");


        if (ipInput) {

            ipInput.addEventListener(
                "keydown",
                (event) => {

                    if (
                        event.key === "Enter"
                    ) {

                        event.preventDefault();

                        loadHTTPAnalysis();
                    }
                }
            );
        }


        /* Initial dashboard load */

        refreshDashboard();


        /* Do NOT automatically request HTTP analysis
           when the IP field is empty. */


        /* Start auto refresh */

        configureRefreshTimer();
    }
);