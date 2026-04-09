/* ═══════════════════════════════════════════════════════
   File Signature Recovery — Frontend Logic
   ═══════════════════════════════════════════════════════ */

const API_BASE = "http://127.0.0.1:7999";
let allRecoveryResults = [];

// ════════════════════════════════════════════════════════
// System Health Check
// ════════════════════════════════════════════════════════

async function checkHealth() {
    const el = document.getElementById("systemStatus");
    try {
        const res = await fetch(`${API_BASE}/health`);
        const data = await res.json();
        const dot = el.querySelector(".status-dot");
        const text = el.querySelector("span:last-child");

        if (data.status === "ok") {
            dot.className = "status-dot online";
            const models = [];
            if (data.models.hybrid) models.push("Hybrid");
            else if (data.models.cnn) models.push("CNN");
            if (data.models.xgboost) models.push("XGB");
            if (data.models.yara) models.push("YARA");
            text.textContent = `Online · ${models.join(" + ")}`;
        }
    } catch {
        const dot = el.querySelector(".status-dot");
        const text = el.querySelector("span:last-child");
        dot.className = "status-dot offline";
        text.textContent = "API Offline";
    }
}

// ════════════════════════════════════════════════════════
// Tab Navigation
// ════════════════════════════════════════════════════════

function switchTab(tabName) {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(t => t.classList.remove("active"));

    document.querySelector(`[data-tab="${tabName}"]`).classList.add("active");
    document.getElementById(`tab-${tabName}`).classList.add("active");
}

// ════════════════════════════════════════════════════════
// Single File Analysis
// ════════════════════════════════════════════════════════

const dropZone = document.getElementById("dropZone");
const fileInput = document.getElementById("fileInput");

dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("drag-over");
});

dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("drag-over");
});

dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("drag-over");
    if (e.dataTransfer.files.length > 0) {
        analyzeFile(e.dataTransfer.files[0]);
    }
});

fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
        analyzeFile(e.target.files[0]);
    }
});

async function analyzeFile(file) {
    document.getElementById("analyzeLoading").style.display = "block";
    document.getElementById("analyzeResults").style.display = "none";

    const formData = new FormData();
    formData.append("file", file);

    try {
        const res = await fetch(`${API_BASE}/analyze`, { method: "POST", body: formData });
        const data = await res.json();

        document.getElementById("analyzeLoading").style.display = "none";
        document.getElementById("analyzeResults").style.display = "block";

        // Update result cards
        document.getElementById("resType").textContent = data.predicted_type || "UNKNOWN";
        document.getElementById("resConfidence").textContent = `Confidence: ${data.confidence || 0}%`;

        const riskLevel = data.risk_level || "LOW";
        document.getElementById("resMalware").textContent = riskLevel;
        document.getElementById("resMalScore").textContent = `Score: ${data.malware_score || 0}`;

        const malwareCard = document.getElementById("resultMalware");
        malwareCard.className = "result-card glass " + (riskLevel === "LOW" ? "safe" : "danger");

        // YARA
        const yaraThreats = data.yara_threats || [];
        document.getElementById("resYara").textContent = yaraThreats.length > 0 ? `${yaraThreats.length} Threat(s)` : "Clean ✓";
        document.getElementById("resYaraDetail").textContent = yaraThreats.length > 0 ? yaraThreats.map(t => t.rule).join(", ") : "No threats detected";

        const yaraCard = document.getElementById("resultYara");
        yaraCard.className = "result-card glass " + (yaraThreats.length > 0 ? "danger" : "safe");

        document.getElementById("resTime").textContent = `${data.analysis_time_ms || 0}ms`;
        document.getElementById("resSize").textContent = `Size: ${formatBytes(data.file_size || 0)}`;

        // Draw histogram
        if (data.byte_histogram) {
            drawHistogram(data.byte_histogram);
            document.getElementById("histogramCard").style.display = "block";
        }

    } catch (e) {
        document.getElementById("analyzeLoading").style.display = "none";
        alert("Analysis failed. Make sure the API server is running.\n\nError: " + e.message);
    }
}

// ════════════════════════════════════════════════════════
// Recovery Scan
// ════════════════════════════════════════════════════════

async function startRecovery() {
    const path = document.getElementById("folderPath").value.trim();
    if (!path) {
        alert("Please enter a folder path.");
        return;
    }

    const recursive = document.getElementById("recursiveCheck").checked;
    const include_recycle_bin = document.getElementById("recycleBinCheck").checked;
    const include_disk_scan = document.getElementById("diskScanCheck").checked;
    
    const btn = document.getElementById("startRecoveryBtn");
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-icon">⏳</span> Recovering...';

    document.getElementById("recoveryProgress").style.display = "block";
    document.getElementById("recoverySummary").style.display = "none";

    try {
        const res = await fetch(`${API_BASE}/recover`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ 
                path, 
                recursive,
                include_recycle_bin, 
                include_disk_scan
            })
        });

        const data = await res.json();
        if (data.error) {
            alert(data.error);
            btn.disabled = false;
            btn.innerHTML = '<span class="btn-icon">🚀</span> Start Recovery';
            return;
        }

        // Poll for progress
        pollRecoveryStatus();

    } catch (e) {
        alert("Recovery failed. Make sure the API is running.\n\nError: " + e.message);
        btn.disabled = false;
        btn.innerHTML = '<span class="btn-icon">🚀</span> Start Recovery';
    }
}

async function pollRecoveryStatus() {
    const interval = setInterval(async () => {
        try {
            const res = await fetch(`${API_BASE}/recover/status`);
            const data = await res.json();

            const progress = data.progress || 0;
            const total = data.total || 0;
            const message = data.message || "";
            
            // Handle progress bar
            let percent = 0;
            if (total > 0) {
                percent = Math.round((progress / total) * 100);
            } else if (message.includes("Disk Carving")) {
                // For disk carving, we use a slower pulse or indeterminate if needed,
                // but main.py provides "Sector X/Y" in the message.
                percent = 50; // Visual indicator it's busy
            } else if (message.includes("Scan")) {
                percent = 10;
            }

            document.getElementById("progressFill").style.width = `${percent}%`;
            document.getElementById("progressText").textContent = total > 0 ? `${progress} / ${total} files` : "Scanning...";
            document.getElementById("progressPercent").textContent = total > 0 ? `${percent}%` : "";
            document.getElementById("progressMessage").textContent = message;

            if (!data.running) {
                clearInterval(interval);

                // Show summary
                const results = data.results || [];
                allRecoveryResults = results;

                const recovered = results.filter(r => r.action === "recovered").length;
                const quarantined = results.filter(r => r.action === "quarantined").length;
                const errors = results.filter(r => r.action === "error").length;

                document.getElementById("sumRecovered").textContent = recovered;
                document.getElementById("sumQuarantined").textContent = quarantined;
                document.getElementById("sumErrors").textContent = errors;
                document.getElementById("sumTotal").textContent = results.length;
                document.getElementById("recoverySummary").style.display = "block";

                // Populate results tab
                renderResults(results);

                const btn = document.getElementById("startRecoveryBtn");
                btn.disabled = false;
                btn.innerHTML = '<span class="btn-icon">🚀</span> Start Recovery';
            }
        } catch {
            clearInterval(interval);
        }
    }, 1000);
}

// ════════════════════════════════════════════════════════
// Results Rendering
// ════════════════════════════════════════════════════════

function renderResults(results) {
    const list = document.getElementById("resultsList");
    const noResults = document.getElementById("noResults");
    const table = document.getElementById("resultsTable");

    if (results.length === 0) {
        noResults.style.display = "block";
        table.style.display = "none";
        return;
    }

    noResults.style.display = "none";
    table.style.display = "block";
    list.innerHTML = "";

    results.forEach(r => {
        const actionBadge = r.action === "recovered"
            ? '<span class="badge badge-recovered">✓ Recovered</span>'
            : r.action === "quarantined"
                ? '<span class="badge badge-quarantined">⚠ Quarantined</span>'
                : '<span class="badge badge-error">✗ Error</span>';

        const riskBadge = r.risk_level === "LOW"
            ? '<span class="badge badge-low">LOW</span>'
            : r.risk_level === "MEDIUM"
                ? '<span class="badge badge-medium">MEDIUM</span>'
                : '<span class="badge badge-high">HIGH</span>';

        const source = r.source || "folder";
        const sourceBadge = source === "disk_scan" 
            ? '<span class="badge badge-disk">💿 DISK</span>' 
            : source === "recycle_bin" 
                ? '<span class="badge badge-bin">🗑️ BIN</span>' 
                : '<span class="badge badge-folder">📁 FOLD</span>';

        const row = document.createElement("div");
        row.className = "result-row";
        row.dataset.action = r.action;
        row.dataset.filename = (r.filename || "").toLowerCase();
        row.innerHTML = `
            <div class="filename" title="${r.filepath || ''}">${r.filename || "unknown"}</div>
            <div class="file-type">${r.predicted_type || "?"}</div>
            <div class="confidence">${r.confidence || 0}%</div>
            <div>${sourceBadge}</div>
            <div>${riskBadge}</div>
            <div>${actionBadge}</div>
        `;
        list.appendChild(row);
    });
}

function filterResults() {
    const search = document.getElementById("searchResults").value.toLowerCase();
    const action = document.getElementById("filterAction").value;

    document.querySelectorAll(".result-row").forEach(row => {
        const matchSearch = row.dataset.filename.includes(search);
        const matchAction = action === "all" || row.dataset.action === action;
        row.style.display = matchSearch && matchAction ? "" : "none";
    });
}

// ════════════════════════════════════════════════════════
// Utilities
// ════════════════════════════════════════════════════════

function formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function drawHistogram(data) {
    const canvas = document.getElementById("histogramCanvas");
    const ctx = canvas.getContext("2d");
    canvas.width = canvas.offsetWidth * 2;
    canvas.height = 400;
    ctx.scale(2, 2);

    const w = canvas.offsetWidth;
    const h = 200;
    const barWidth = w / 256;
    const maxVal = Math.max(...data, 0.001);

    // Background
    ctx.fillStyle = "rgba(0, 0, 0, 0.2)";
    ctx.fillRect(0, 0, w, h);

    // Draw bars
    data.forEach((val, i) => {
        const barHeight = (val / maxVal) * (h - 20);
        const hue = Math.floor((i / 256) * 270);
        ctx.fillStyle = `hsla(${hue}, 70%, 55%, 0.8)`;
        ctx.fillRect(i * barWidth, h - barHeight - 10, Math.max(barWidth - 0.5, 1), barHeight);
    });

    // Labels
    ctx.fillStyle = "#94a3b8";
    ctx.font = "10px Inter";
    ctx.textAlign = "center";
    for (let i = 0; i <= 255; i += 32) {
        ctx.fillText(`0x${i.toString(16).toUpperCase().padStart(2, "0")}`, i * barWidth, h - 1);
    }
}

// ════════════════════════════════════════════════════════
// Initialize
// ════════════════════════════════════════════════════════

checkHealth();
setInterval(checkHealth, 10000);
