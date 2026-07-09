(() => {
    "use strict";

    const dataRoot = document.body.dataset.dataRoot || "data";
    const state = { observations: [], filteredObservations: [] };

    const byId = (id) => document.getElementById(id);

    function pathValue(object, path) {
        return path.split(".").reduce((value, key) => {
            if (value === null || value === undefined || typeof value !== "object") return undefined;
            return value[key];
        }, object);
    }

    function firstValue(object, paths, fallback = undefined) {
        for (const path of paths) {
            const value = pathValue(object, path);
            if (value !== null && value !== undefined) return value;
        }
        return fallback;
    }

    function firstNumber(object, paths, fallback = null) {
        const value = firstValue(object, paths);
        const number = Number(value);
        return Number.isFinite(number) ? number : fallback;
    }

    function normalizePercentage(value) {
        const number = Number(value);
        if (!Number.isFinite(number)) return null;
        return number;
    }

    function normalizeMetric(value, fallbackTotal = null) {
        if (value === null || value === undefined) {
            return { count: null, total: fallbackTotal, percentage: null };
        }
        if (typeof value === "number") {
            return { count: null, total: fallbackTotal, percentage: normalizePercentage(value) };
        }
        const count = firstNumber(value, ["count", "present", "numerator", "value"]);
        const total = firstNumber(value, ["total", "denominator", "queried", "eligible"], fallbackTotal);
        let percentage = normalizePercentage(firstValue(value, ["percentage", "percent", "rate", "adoption"]));
        if (percentage === null && count !== null && total) percentage = count / total * 100;
        return { count, total, percentage };
    }

    function metricAt(object, paths, fallbackTotal = null) {
        return normalizeMetric(firstValue(object, paths), fallbackTotal);
    }

    function formatNumber(value) {
        return Number.isFinite(value) ? new Intl.NumberFormat("en-US").format(value) : "—";
    }

    function formatPercent(value) {
        return Number.isFinite(value) ? `${value.toFixed(value >= 10 ? 1 : 2).replace(/\.?0+$/, "")}%` : "—";
    }

    function metricText(metric) {
        if (metric.count !== null && metric.total !== null) {
            return `${formatNumber(metric.count)} of ${formatNumber(metric.total)} (${formatPercent(metric.percentage)})`;
        }
        if (metric.count !== null) return formatNumber(metric.count);
        return formatPercent(metric.percentage);
    }

    function formatDate(value, includeTime = true) {
        if (!value) return "Unknown";
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return String(value);
        const options = includeTime
            ? { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit", timeZoneName: "short" }
            : { dateStyle: "medium" };
        return new Intl.DateTimeFormat("en-US", options).format(date);
    }

    function escapeHtml(value) {
        return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    function titleCase(value) {
        return String(value || "unknown")
            .replaceAll("_", " ")
            .replace(/\b\w/g, (letter) => letter.toUpperCase());
    }

    async function fetchJson(filename) {
        const response = await fetch(`${dataRoot}/${filename}`, { cache: "no-store" });
        if (!response.ok) throw new Error(`${filename}: HTTP ${response.status}`);
        return response.json();
    }

    function normalizeLatest(latest) {
        const metrics = latest.metrics || {};
        const denominators = metrics.denominators || {};
        const domainCount = firstNumber(latest, [
            "cohort.count", "cohort.domain_count", "scan.cohort_count", "metadata.unique_domains",
            "metrics.denominators.domains", "metrics.unique_domains",
        ]);
        const httpsNames = firstNumber(denominators, ["https_names", "queried_https_names", "https_queries"]);
        const svcbNames = firstNumber(denominators, ["svcb_names", "queried_svcb_names", "svcb_queries"]);
        const usableRecords = firstNumber(denominators, ["usable_https_rrsets", "usable_records", "usable_rrsets", "https_present_rrsets"]);
        const presentRecords = firstNumber(denominators, ["https_present_rrsets", "present_rrsets", "present_records"]);

        const adoption = {
            https: metricAt(metrics, ["adoption.https", "adoption.https_records", "adoption.overall", "adoption.overall_adoption", "https_adoption"], httpsNames),
            root: metricAt(metrics, ["adoption.root_https", "adoption.root", "adoption.root_adoption"], domainCount),
            www: metricAt(metrics, ["adoption.www_https", "adoption.www", "adoption.www_adoption"], domainCount),
            svcb: metricAt(metrics, ["adoption.svcb", "adoption.svcb_records", "adoption.svcb_adoption"], svcbNames),
        };

        const validity = {
            valid: metricAt(metrics, ["validity.overall.valid", "validity.valid", "validity.valid_records"], presentRecords),
            invalid: metricAt(metrics, ["validity.overall.invalid", "validity.invalid", "validity.invalid_records"], presentRecords),
            incompatible: metricAt(metrics, ["validity.overall.valid_but_incompatible", "validity.valid_but_incompatible", "validity.incompatible"], presentRecords),
            unknown: metricAt(metrics, ["validity.overall.unknown", "validity.unknown"], presentRecords),
        };

        const featureDefinitions = [
            ["H3 advertised", ["features.h3_advertised", "features.http3_support"]],
            ["ECH advertised", ["features.ech_advertised", "features.ech_deployment"]],
            ["ALPN advertised", ["features.alpn_advertised"]],
            ["no-default-alpn", ["features.no_default_alpn"]],
            ["IPv4 hints", ["features.ipv4hint", "features.ipv4_hints"]],
            ["IPv6 hints", ["features.ipv6hint", "features.ipv6_hints"]],
            ["Custom port", ["features.custom_port", "features.custom_ports"]],
        ];
        const features = featureDefinitions.map(([label, paths]) => ({
            label,
            ...metricAt(metrics, paths, usableRecords),
        }));

        return {
            raw: latest,
            scanId: firstValue(latest, ["scan.id", "metadata.scan_id", "scan_id"]),
            scanDate: firstValue(latest, ["scan.completed_at", "scan.started_at", "metadata.scan_date", "scan_date"]),
            domainCount,
            httpsNames,
            svcbNames,
            usableRecords,
            adoption,
            validity,
            features,
            observations: Array.isArray(latest.observations) ? latest.observations : [],
        };
    }

    function normalizeHistory(history) {
        const entries = Array.isArray(history) ? history : (history.entries || history.history || []);
        return entries.map((entry) => {
            const metrics = entry.metrics || {};
            const total = firstNumber(metrics, ["denominators.https_names", "denominators.queried_https_names"]);
            return {
                date: firstValue(entry, ["scan_date", "scan.completed_at", "metadata.scan_date"]),
                scanId: firstValue(entry, ["scan_id", "scan.id"]),
                schemaVersion: Number(entry.schema_version || 1),
                adoption: metricAt(metrics, ["adoption.https", "adoption.https_records", "adoption.overall", "adoption.overall_adoption", "https_adoption"], total),
            };
        }).filter((entry) => entry.date && Number.isFinite(entry.adoption.percentage));
    }

    function renderLatest(latest, history) {
        byId("scanDate").textContent = formatDate(latest.scanDate);
        byId("footerScanDate").textContent = formatDate(latest.scanDate, false);
        byId("domainCountValue").textContent = formatNumber(latest.domainCount);
        const totalQueries = [latest.httpsNames, latest.svcbNames].filter(Number.isFinite).reduce((a, b) => a + b, 0);
        byId("queryCountDetail").textContent = totalQueries ? `${formatNumber(totalQueries)} DNS names queried by record type` : "Query denominator unavailable";

        byId("httpsAdoptionValue").textContent = formatPercent(latest.adoption.https.percentage);
        byId("httpsAdoptionDetail").textContent = metricText(latest.adoption.https);
        byId("rootAdoption").textContent = metricText(latest.adoption.root);
        byId("wwwAdoption").textContent = metricText(latest.adoption.www);
        byId("svcbAdoption").textContent = latest.adoption.svcb.total
            ? metricText(latest.adoption.svcb)
            : "Not measured for this web cohort";

        byId("validRecordsValue").textContent = latest.validity.valid.count !== null ? formatNumber(latest.validity.valid.count) : formatPercent(latest.validity.valid.percentage);
        byId("validRecordsDetail").textContent = metricText(latest.validity.valid);
        const http3 = latest.features.find((feature) => feature.label === "H3 advertised");
        byId("http3Value").textContent = formatPercent(http3?.percentage);
        byId("http3Detail").textContent = metricText(http3 || normalizeMetric(null));

        byId("featureSummary").innerHTML = latest.features.map((feature) =>
            `<span class="feature-pill"><strong>${escapeHtml(feature.label)}:</strong> ${escapeHtml(metricText(feature))}</span>`
        ).join("");

        const validityLabels = [
            ["Valid", latest.validity.valid],
            ["Invalid", latest.validity.invalid],
            ["Valid but incompatible", latest.validity.incompatible],
            ["Unknown / not assessed", latest.validity.unknown],
        ];
        byId("validitySummary").innerHTML = validityLabels.map(([label, metric]) =>
            `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(metricText(metric))}</dd></div>`
        ).join("");

        if (window.RFC9460Charts) window.RFC9460Charts.render(latest, history);
    }

    function identityValue(change, key) {
        return firstValue(change, [key, `identity.${key}`, `after.${key}`, `before.${key}`], "—");
    }

    function describeChange(kind, change) {
        if (typeof change === "string") return change;
        if (kind === "changed") {
            const fields = change.fields || change.changed_fields;
            if (Array.isArray(fields) && fields.length) return `Changed ${fields.join(", ")}`;
            if (fields && typeof fields === "object") return `Changed ${Object.keys(fields).join(", ")}`;
            return change.summary || "RRset content changed";
        }
        return change.summary || (kind === "gained" ? "Record newly observed" : "Record no longer observed");
    }

    function renderChanges(changes) {
        const comparable = changes.comparable !== false;
        const fromScan = changes.from_scan || changes.fromScan;
        const toScan = changes.to_scan || changes.toScan;
        const rows = [];
        for (const kind of ["gained", "lost", "changed"]) {
            for (const item of (Array.isArray(changes[kind]) ? changes[kind] : [])) rows.push({ kind, item });
        }

        if (!comparable) {
            byId("changeContext").textContent = changes.message || changes.reason || "This is the first detailed schema-v2 scan, so no comparable per-name predecessor exists yet.";
        } else {
            const summary = changes.summary || {};
            const summaryText = ["gained", "lost", "changed"].map((key) => `${formatNumber(Number(summary[key] ?? changes[key]?.length ?? 0))} ${key}`).join(" · ");
            byId("changeContext").textContent = `${summaryText}${fromScan || toScan ? ` between ${fromScan || "the previous scan"} and ${toScan || "the current scan"}` : ""}.`;
        }

        byId("changesTable").innerHTML = rows.length ? rows.slice(0, 100).map(({ kind, item }) => {
            const name = identityValue(item, "name");
            const domain = identityValue(item, "domain");
            const rrtype = identityValue(item, "rrtype");
            const badgeClass = kind === "gained" ? "text-bg-success" : kind === "lost" ? "text-bg-secondary" : "text-bg-warning";
            return `<tr><td><span class="badge ${badgeClass}">${escapeHtml(titleCase(kind))}</span></td><td><span class="domain-name">${escapeHtml(domain)}</span><span class="queried-name">${escapeHtml(name)}</span></td><td><code>${escapeHtml(rrtype)}</code></td><td>${escapeHtml(describeChange(kind, item))}</td></tr>`;
        }).join("") : `<tr><td colspan="4" class="empty-state">${comparable ? "No record changes were reported." : "Detailed comparisons will begin with the next compatible scan."}</td></tr>`;
    }

    function observationView(observation, index) {
        const validation = observation.validation || {};
        const error = observation.error || observation.query_error;
        const present = observation.present ?? observation.has_record ?? observation.has_https_record ?? false;
        const validity = String(validation.status || observation.validity || "").toLowerCase();
        const queryStatus = String(observation.status || observation.query_status || "").toLowerCase();
        let category = present ? "present" : "absent";
        if (error || ["error", "timeout"].includes(queryStatus)) category = "error";
        else if (present && validity.includes("incompatible")) category = "incompatible";
        else if (present && validity.includes("invalid")) category = "invalid";

        return {
            raw: observation,
            index,
            domain: observation.domain || observation.base_domain || "—",
            name: observation.name || observation.full_domain || observation.qname || "—",
            variant: observation.variant || observation.subdomain || "",
            rrtype: observation.rrtype || observation.record_type || observation.type || "—",
            resolver: Array.isArray(observation.resolver) ? observation.resolver.join(", ") : (observation.resolver || observation.dns_server || "—"),
            category,
            validity,
            status: error ? `Error: ${error}` : (present ? (validity || queryStatus || "present") : (queryStatus || "absent")),
            features: observationFeatureLabels(observation),
        };
    }

    function valueIsPresent(value) {
        if (value === true) return true;
        if (value === false || value === null || value === undefined || value === "") return false;
        if (Array.isArray(value)) return value.length > 0;
        if (typeof value === "object") return Object.keys(value).length > 0;
        return true;
    }

    function observationFeatureLabels(observation) {
        const labels = [];
        const features = observation.features || {};
        const names = {
            h3_advertised: "H3 advertised", http3: "H3 advertised", http3_support: "H3 advertised",
            http2: "HTTP/2", ech_advertised: "ECH advertised", ech: "ECH advertised",
            ech_config: "ECH advertised", ipv4hint: "IPv4 hints", ipv4_hints: "IPv4 hints",
            ipv6hint: "IPv6 hints", ipv6_hints: "IPv6 hints", custom_port: "Custom port",
        };
        for (const [key, value] of Object.entries(features)) {
            if (valueIsPresent(value)) labels.push(names[key] || titleCase(key));
        }
        return [...new Set(labels)].slice(0, 6);
    }

    function badgeForObservation(observation) {
        const labels = { present: "Present", absent: "Absent", invalid: "Invalid", incompatible: "Incompatible", error: "Query error" };
        return `<span class="badge badge-${observation.category}">${escapeHtml(labels[observation.category] || titleCase(observation.category))}</span>`;
    }

    function renderObservations() {
        const search = byId("domainSearch").value.trim().toLowerCase();
        const filter = byId("statusFilter").value;
        state.filteredObservations = state.observations.filter((observation) => {
            const haystack = `${observation.domain} ${observation.name} ${observation.rrtype} ${observation.resolver} ${observation.status}`.toLowerCase();
            return (!search || haystack.includes(search)) && (filter === "all" || observation.category === filter);
        });

        byId("observationCount").textContent = `Showing ${formatNumber(state.filteredObservations.length)} of ${formatNumber(state.observations.length)} observations`;
        byId("observationsTable").innerHTML = state.filteredObservations.length ? state.filteredObservations.map((observation) => {
            const features = observation.features.length ? observation.features.map((feature) => `<span class="badge text-bg-light border me-1">${escapeHtml(feature)}</span>`).join("") : '<span class="text-secondary">—</span>';
            return `<tr><td><span class="domain-name">${escapeHtml(observation.domain)}</span><span class="queried-name">${escapeHtml(observation.name)}${observation.variant ? ` · ${escapeHtml(observation.variant)}` : ""}</span></td><td><code>${escapeHtml(observation.rrtype)}</code></td><td>${escapeHtml(observation.resolver)}</td><td>${badgeForObservation(observation)}<span class="d-block queried-name mt-1">${escapeHtml(observation.status)}</span></td><td>${features}</td><td><button class="btn btn-sm btn-outline-primary observation-detail" type="button" data-index="${observation.index}">Inspect</button></td></tr>`;
        }).join("") : '<tr><td colspan="6" class="empty-state">No observations match this filter.</td></tr>';
    }

    function showObservation(index) {
        const observation = state.observations.find((item) => item.index === index);
        if (!observation) return;
        byId("modalTitle").textContent = `${observation.name} ${observation.rrtype} observation`;
        byId("modalBody").innerHTML = `
            <div class="detail-grid">
                <div class="detail-field"><span>Base domain</span><strong>${escapeHtml(observation.domain)}</strong></div>
                <div class="detail-field"><span>Resolver</span><strong>${escapeHtml(observation.resolver)}</strong></div>
                <div class="detail-field"><span>Classification</span><strong>${escapeHtml(observation.status)}</strong></div>
            </div>
            <h3 class="h6">Complete retained observation</h3>
            <pre class="raw-record"><code id="observationJson"></code></pre>`;
        byId("observationJson").textContent = JSON.stringify(observation.raw, null, 2);
        bootstrap.Modal.getOrCreateInstance(byId("detailModal")).show();
    }

    function showFailure(error) {
        const status = byId("dataStatus");
        status.className = "alert alert-danger";
        status.innerHTML = `<strong>Current data could not be loaded.</strong> ${escapeHtml(error.message)}. No cached headline values are shown; inspect the generated JSON or the Actions run.`;
        byId("changesTable").innerHTML = '<tr><td colspan="4" class="empty-state">Change data unavailable.</td></tr>';
        byId("observationsTable").innerHTML = '<tr><td colspan="6" class="empty-state">Observation data unavailable.</td></tr>';
    }

    async function initialize() {
        try {
            const latestRaw = await fetchJson("latest.json");
            const [historyResult, changesResult] = await Promise.allSettled([
                fetchJson("history.json"),
                fetchJson("changes.json"),
            ]);
            const latest = normalizeLatest(latestRaw);
            const history = historyResult.status === "fulfilled"
                ? normalizeHistory(historyResult.value)
                : [];
            state.observations = latest.observations.map(observationView);
            renderLatest(latest, history);
            if (changesResult.status === "fulfilled") {
                renderChanges(changesResult.value);
            } else {
                byId("changeContext").textContent = "Current observations loaded, but change data is unavailable.";
                byId("changesTable").innerHTML = '<tr><td colspan="4" class="empty-state">Change data unavailable.</td></tr>';
            }
            renderObservations();
            if (historyResult.status === "rejected" || changesResult.status === "rejected") {
                const status = byId("dataStatus");
                status.className = "alert alert-warning";
                status.textContent = "Current scan loaded. One or more historical views could not be loaded.";
            }
        } catch (error) {
            console.error(error);
            showFailure(error);
        }
    }

    byId("domainSearch").addEventListener("input", renderObservations);
    byId("statusFilter").addEventListener("change", renderObservations);
    byId("observationsTable").addEventListener("click", (event) => {
        const button = event.target.closest(".observation-detail");
        if (button) showObservation(Number(button.dataset.index));
    });
    initialize();
})();
