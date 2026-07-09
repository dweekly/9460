(() => {
    "use strict";

    const palette = {
        primary: "#3156b8",
        secondary: "#8ea1d6",
        success: "#198754",
        warning: "#e0a800",
        danger: "#dc3545",
        muted: "#dfe5ef",
        ink: "#172033",
    };
    const instances = {};

    function destroy(name) {
        if (instances[name]) instances[name].destroy();
    }

    function metricCount(metric) {
        if (Number.isFinite(metric?.count)) return metric.count;
        if (Number.isFinite(metric?.percentage) && Number.isFinite(metric?.total)) return metric.percentage / 100 * metric.total;
        return 0;
    }

    function commonOptions() {
        return {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: "bottom", labels: { usePointStyle: true, padding: 18 } },
                tooltip: { padding: 10 },
            },
        };
    }

    function renderAdoption(latest) {
        destroy("adoption");
        const metric = latest.adoption.https;
        const present = metricCount(metric);
        const total = Number.isFinite(metric.total) ? metric.total : present;
        instances.adoption = new Chart(document.getElementById("adoptionChart"), {
            type: "doughnut",
            data: {
                labels: ["HTTPS RRset observed", "No HTTPS RRset observed"],
                datasets: [{ data: [present, Math.max(total - present, 0)], backgroundColor: [palette.success, palette.muted], borderWidth: 0 }],
            },
            options: { ...commonOptions(), cutout: "68%" },
        });
    }

    function renderFeatures(latest) {
        destroy("features");
        instances.features = new Chart(document.getElementById("featuresChart"), {
            type: "bar",
            data: {
                labels: latest.features.map((feature) => feature.label),
                datasets: [{
                    label: "Advertised by eligible records (%)",
                    data: latest.features.map((feature) => feature.percentage ?? 0),
                    backgroundColor: [palette.primary, "#7a5ab5", palette.secondary, "#cc7a28", "#2684a8", "#50a37f", palette.warning],
                    borderRadius: 5,
                }],
            },
            options: {
                ...commonOptions(),
                scales: {
                    y: { beginAtZero: true, suggestedMax: 100, ticks: { callback: (value) => `${value}%` }, grid: { color: "#eef1f6" } },
                    x: { grid: { display: false } },
                },
                plugins: { ...commonOptions().plugins, legend: { display: false } },
            },
        });
    }

    function renderValidity(latest) {
        destroy("validity");
        const metrics = [latest.validity.valid, latest.validity.incompatible, latest.validity.invalid, latest.validity.unknown];
        instances.validity = new Chart(document.getElementById("validityChart"), {
            type: "doughnut",
            data: {
                labels: ["Valid", "Valid but incompatible", "Invalid", "Unknown / not assessed"],
                datasets: [{ data: metrics.map(metricCount), backgroundColor: [palette.success, palette.warning, palette.danger, palette.muted], borderWidth: 0 }],
            },
            options: { ...commonOptions(), cutout: "64%" },
        });
    }

    function renderHistory(history) {
        destroy("history");
        instances.history = new Chart(document.getElementById("historyChart"), {
            type: "line",
            data: {
                labels: history.map((entry) => entry.date),
                datasets: [{
                    label: "HTTPS queried-name adoption",
                    data: history.map((entry) => entry.adoption.percentage),
                    borderColor: palette.primary,
                    backgroundColor: "rgba(49, 86, 184, .12)",
                    pointBackgroundColor: history.map((entry) => entry.schemaVersion >= 2 ? palette.primary : palette.secondary),
                    pointRadius: history.map((entry) => entry.schemaVersion >= 2 ? 3 : 1.5),
                    borderWidth: 2,
                    fill: true,
                    tension: .16,
                }],
            },
            options: {
                ...commonOptions(),
                scales: {
                    y: { beginAtZero: true, suggestedMax: 25, ticks: { callback: (value) => `${value}%` }, title: { display: true, text: "Queried names with HTTPS RRsets" } },
                    x: {
                        ticks: {
                            autoSkip: true,
                            maxTicksLimit: 12,
                            callback(value) {
                                const raw = this.getLabelForValue(value);
                                const date = new Date(raw);
                                return Number.isNaN(date.getTime()) ? raw : date.toLocaleDateString("en-US", { month: "short", year: "2-digit" });
                            },
                        },
                        grid: { display: false },
                    },
                },
                plugins: {
                    ...commonOptions().plugins,
                    tooltip: {
                        callbacks: {
                            title: (items) => items[0] ? new Date(items[0].label).toLocaleString() : "",
                            label: (context) => `${context.parsed.y.toFixed(2)}% adoption`,
                            afterLabel: (context) => `Schema v${history[context.dataIndex]?.schemaVersion || 1}`,
                        },
                    },
                },
            },
        });
    }

    window.RFC9460Charts = {
        render(latest, history) {
            if (typeof Chart === "undefined") return;
            Chart.defaults.color = "#667085";
            Chart.defaults.font.family = "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";
            renderAdoption(latest);
            renderFeatures(latest);
            renderValidity(latest);
            renderHistory(history);
        },
    };
})();
