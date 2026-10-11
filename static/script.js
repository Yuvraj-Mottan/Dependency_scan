// =====================================================
// GET CURRENT SCAN ID
// =====================================================

function getScanId() {

    const parts =
        window.location.pathname.split("/");

    const lastPart =
        parts[parts.length - 1];

    if (
        lastPart &&
        !isNaN(lastPart)
    ) {
        return lastPart;
    }

    return null;
}



// =====================================================
// PAGE INITIALIZATION
// =====================================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        const scanId = getScanId();


        if (scanId) {

            showDashboard();

            loadScan();

        }

        else {

            showAnalyzePage();

        }

    }
);



// =====================================================
// SHOW ANALYZE PAGE
// =====================================================

function showAnalyzePage() {

    document
        .getElementById("analyze-page")
        .classList.remove("hidden");


    document
        .getElementById("dashboard-page")
        .classList.add("hidden");

}



// =====================================================
// SHOW DASHBOARD
// =====================================================

function showDashboard() {

    document
        .getElementById("analyze-page")
        .classList.add("hidden");


    document
        .getElementById("dashboard-page")
        .classList.remove("hidden");

}



// =====================================================
// GO TO ANALYZE PAGE
// =====================================================

function goToAnalyze() {

    window.location.href =
        "/dashboard";

}



// =====================================================
// ANALYZE REPOSITORY
// =====================================================

async function analyzeRepository() {

    const input =
        document.getElementById(
            "repository-url"
        );


    const button =
        document.getElementById(
            "analyze-btn"
        );


    const error =
        document.getElementById(
            "error-message"
        );


    const loading =
        document.getElementById(
            "loading-message"
        );


    const url =
        input.value.trim();


    // -----------------------------------------------
    // Validate input
    // -----------------------------------------------

    if (!url) {

        error.textContent =
            "Please enter a GitHub repository URL.";

        return;

    }


    if (!url.startsWith("https://github.com/")) {

        error.textContent =
            "Please enter a valid GitHub repository URL.";

        return;

    }


    // -----------------------------------------------
    // UI
    // -----------------------------------------------

    error.textContent = "";

    button.disabled = true;

    button.textContent =
        "Analyzing...";

    loading.style.display =
        "flex";


    try {

        // -------------------------------------------
        // Send repository to FastAPI
        // -------------------------------------------

        const response =
            await fetch(
                "/scan",
                {

                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        url: url
                    })

                }
            );


        const data =
            await response.json();


        // -------------------------------------------
        // Handle backend error
        // -------------------------------------------

        if (!response.ok) {

            throw new Error(
                data.detail ||
                data.error ||
                "Repository scan failed."
            );

        }


        if (data.error) {

            throw new Error(
                data.error
            );

        }


        // -------------------------------------------
        // Scan successful
        // -------------------------------------------

        console.log(
            "Scan completed:",
            data
        );


        const scanId =
            data.scan_id;


        // -------------------------------------------
        // Open dashboard for this scan
        // -------------------------------------------

        window.location.href =
            `/dashboard/${scanId}`;


    }

    catch (err) {

        console.error(
            "Scan failed:",
            err
        );


        error.textContent =
            err.message ||
            "Unable to scan repository.";


        button.disabled =
            false;


        button.textContent =
            "Analyze Repository";


        loading.style.display =
            "none";

    }

}



// =====================================================
// FORMAT DATE
// =====================================================

function formatDate(dateString) {

    if (!dateString) {

        return "Not available";

    }


    const date =
        new Date(dateString);


    return date.toLocaleString();

}



// =====================================================
// LOAD SCAN
// =====================================================

async function loadScan() {

    const scanId =
        getScanId();


    if (!scanId) {

        return;

    }


    try {

        const response =
            await fetch(
                `/scan/${scanId}`
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Failed to load scan."
            );

        }


        if (data.error) {

            throw new Error(
                data.error
            );

        }


        console.log(
            "Scan:",
            data
        );


        displayScan(data);


        // Load individual vulnerabilities

        loadVulnerabilities(
            scanId
        );


    }

    catch (error) {

        console.error(
            "Failed to load scan:",
            error
        );


        document
            .getElementById("repository")
            .textContent =
            "Scan not found";

    }

}



// =====================================================
// DISPLAY SCAN
// =====================================================

function displayScan(data) {


    // Repository

    document
        .getElementById("repository")
        .textContent =
        data.repository;


    // Status

    document
        .getElementById("status")
        .textContent =
        data.status;


    document
        .getElementById("scan-status")
        .textContent =
        data.status;


    // Dependencies

    document
        .getElementById("dependencies")
        .textContent =
        data.dependencies;


    // Vulnerabilities

    document
        .getElementById("vulnerabilities")
        .textContent =
        data.vulnerabilities;


    // Security score

    const score =
        Number(data.security_score);


    document
        .getElementById("security-score")
        .textContent =
        score;


    document
        .getElementById("score-circle-number")
        .textContent =
        score;


    // Security level

    const level =
        data.security_level;


    const badge =
        document.getElementById(
            "security-level"
        );


    badge.textContent =
        level;


    setSecurityBadge(
        badge,
        level
    );


    // Scan time

    document
        .getElementById("scan-time")
        .textContent =
        formatDate(
            data.scan_time
        );


    // Scan information

    document
        .getElementById("scan-id")
        .textContent =
        data.id;


    document
        .getElementById("started-at")
        .textContent =
        formatDate(
            data.scan_time
        );


    document
        .getElementById("finished-at")
        .textContent =
        formatDate(
            data.finished_at
        );


    // Severity

    displaySeverity(data);


    // Score message

    displayScoreMessage(
        score,
        level
    );

}



// =====================================================
// SECURITY BADGE
// =====================================================

function setSecurityBadge(
    element,
    level
) {

    element.className =
        "security-badge";


    if (level === "LOW") {

        element.classList.add(
            "badge-low"
        );

    }

    else if (level === "MEDIUM") {

        element.classList.add(
            "badge-medium"
        );

    }

    else if (level === "HIGH") {

        element.classList.add(
            "badge-high"
        );

    }

    else if (level === "CRITICAL") {

        element.classList.add(
            "badge-critical"
        );

    }

}



// =====================================================
// DISPLAY SEVERITY
// =====================================================

function displaySeverity(data) {

    const severity =
        data.severity || {};


    const critical =
        severity.critical || 0;


    const high =
        severity.high || 0;


    const medium =
        severity.medium || 0;


    const low =
        severity.low || 0;


    const unknown =
        severity.unknown || 0;


    document
        .getElementById("critical")
        .textContent =
        critical;


    document
        .getElementById("high")
        .textContent =
        high;


    document
        .getElementById("medium")
        .textContent =
        medium;


    document
        .getElementById("low")
        .textContent =
        low;


    document
        .getElementById("unknown")
        .textContent =
        unknown;


    const max =
        Math.max(
            critical,
            high,
            medium,
            low,
            unknown,
            1
        );


    document
        .getElementById("critical-bar")
        .style.width =
        `${critical / max * 100}%`;


    document
        .getElementById("high-bar")
        .style.width =
        `${high / max * 100}%`;


    document
        .getElementById("medium-bar")
        .style.width =
        `${medium / max * 100}%`;


    document
        .getElementById("low-bar")
        .style.width =
        `${low / max * 100}%`;


    document
        .getElementById("unknown-bar")
        .style.width =
        `${unknown / max * 100}%`;

}



// =====================================================
// SCORE MESSAGE
// =====================================================

function displayScoreMessage(
    score,
    level
) {

    const element =
        document.getElementById(
            "score-message"
        );


    if (level === "LOW") {

        element.textContent =
            "Your dependencies are relatively secure.";

    }

    else if (level === "MEDIUM") {

        element.textContent =
            "Some security issues need attention.";

    }

    else if (level === "HIGH") {

        element.textContent =
            "Significant security issues detected.";

    }

    else {

        element.textContent =
            "Critical security issues detected.";

    }

}



// =====================================================
// LOAD INDIVIDUAL VULNERABILITIES
// =====================================================

async function loadVulnerabilities(
    scanId
) {

    const table =
        document.getElementById(
            "vulnerability-table"
        );


    try {

        const response =
            await fetch(
                `/scan/${scanId}/vulnerabilities`
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Failed to load vulnerabilities."
            );

        }


        const vulnerabilities =
            data.vulnerabilities || [];


        // -------------------------------------------
        // No vulnerabilities
        // -------------------------------------------

        if (
            vulnerabilities.length === 0
        ) {

            table.innerHTML = `
                <tr>

                    <td
                        colspan="8"
                        class="no-vulnerabilities"
                    >

                        ✓ No vulnerabilities found

                    </td>

                </tr>
            `;

            return;

        }


        // -------------------------------------------
        // Create rows
        // -------------------------------------------

        table.innerHTML = "";


        vulnerabilities.forEach(
            vulnerability => {

                const row =
                    document.createElement("tr");


                const severity =
                    vulnerability.severity ||
                    "UNKNOWN";


                const severityClass =
                    getSeverityClass(
                        severity
                    );


                row.innerHTML = `

                    <td>

                        <span
                            class="badge ${severityClass}"
                        >

                            ${escapeHtml(
                                severity
                            )}

                        </span>

                    </td>


                    <td>

                        <strong>

                            ${escapeHtml(
                                vulnerability.id ||
                                "Unknown"
                            )}

                        </strong>

                    </td>


                    <td class="summary-cell">

                        ${escapeHtml(
                            vulnerability.summary ||
                            "No summary available"
                        )}

                    </td>


                    <td>

                        <strong>

                            ${escapeHtml(
                                vulnerability.dependency ||
                                "-"
                            )}

                        </strong>

                        <small>

                            ${escapeHtml(
                                vulnerability.ecosystem ||
                                ""
                            )}

                        </small>

                    </td>


                    <td>

                        ${escapeHtml(
                            vulnerability.version ||
                            "-"
                        )}

                    </td>


                    <td>

                        <span class="type-badge">

                            ${escapeHtml(
                                vulnerability.dependency_type ||
                                "-"
                            )}

                        </span>

                    </td>


                    <td>

                        ${vulnerability.depth ?? "-"}

                    </td>


                    <td>

                        ${
                            vulnerability.fixed_version
                            ?
                            escapeHtml(
                                vulnerability.fixed_version
                            )
                            :
                            "Not available"
                        }

                    </td>

                `;


                table.appendChild(row);

            }
        );

    }

    catch (error) {

        console.error(
            "Failed to load vulnerabilities:",
            error
        );


        table.innerHTML = `

            <tr>

                <td
                    colspan="8"
                    class="loading"
                >

                    Failed to load vulnerabilities.

                </td>

            </tr>

        `;

    }

}



// =====================================================
// GET SEVERITY CSS CLASS
// =====================================================

function getSeverityClass(
    severity
) {

    switch (
        severity.toUpperCase()
    ) {

        case "CRITICAL":

            return "badge-critical";


        case "HIGH":

            return "badge-high";


        case "MODERATE":
        case "MEDIUM":

            return "badge-medium";


        case "LOW":

            return "badge-low";


        default:

            return "badge-unknown";

    }

}



// =====================================================
// ESCAPE HTML
// =====================================================

function escapeHtml(value) {

    const div =
        document.createElement("div");


    div.textContent =
        value;


    return div.innerHTML;

}



// =====================================================
// ENTER KEY SUPPORT
// =====================================================

document.addEventListener(
    "keydown",
    function (event) {

        if (
            event.key === "Enter" &&
            document.activeElement.id ===
                "repository-url"
        ) {

            analyzeRepository();

        }

    }
);