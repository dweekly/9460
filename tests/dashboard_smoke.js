"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const dashboardScript = fs.readFileSync(path.join(root, "docs/assets/js/main.js"), "utf8");
const currentLatest = JSON.parse(
    fs.readFileSync(path.join(root, "docs/data/latest.json"), "utf8"),
);

function formatNumber(value) {
    return new Intl.NumberFormat("en-US").format(value);
}

function formatPercent(value) {
    return `${value.toFixed(value >= 10 ? 1 : 2).replace(/\.?0+$/, "")}%`;
}

class ElementStub {
    constructor(id) {
        this.id = id;
        this.textContent = "";
        this.innerHTML = "";
        this.className = "";
        this.value = id === "statusFilter" ? "all" : "";
        this.dataset = {};
        this.listeners = new Map();
    }

    addEventListener(type, handler) {
        this.listeners.set(type, handler);
    }
}

function jsonResponse(relativePath, transform = (value) => value) {
    const value = JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
    return {
        ok: true,
        status: 200,
        json: async () => transform(value),
    };
}

async function render(fetchOverride) {
    const elements = new Map();
    const document = {
        body: { dataset: { dataRoot: "docs/data" } },
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, new ElementStub(id));
            return elements.get(id);
        },
    };
    const fetch = fetchOverride || (async (relativePath) => jsonResponse(relativePath));
    const context = vm.createContext({
        console,
        document,
        fetch,
        setTimeout,
        clearTimeout,
    });
    context.window = context;
    vm.runInContext(dashboardScript, context, { filename: "main.js" });
    await new Promise((resolve) => setTimeout(resolve, 100));
    return elements;
}

async function testCurrentData() {
    const elements = await render();
    const https = currentLatest.metrics.adoption.https;
    const h3 = currentLatest.metrics.features.h3_advertised;
    const observationCount = currentLatest.observations.length;
    const absentCount = currentLatest.observations.filter((observation) =>
        !observation.present
        && !observation.error
        && !["error", "timeout"].includes(observation.status)
    ).length;
    assert.equal(
        elements.get("httpsAdoptionValue").textContent,
        formatPercent(https.percentage),
    );
    assert.equal(
        elements.get("httpsAdoptionDetail").textContent,
        `${formatNumber(https.count)} of ${formatNumber(https.denominator)} (${formatPercent(https.percentage)})`,
    );
    assert.equal(elements.get("http3Value").textContent, formatPercent(h3.percentage));
    assert.equal(
        elements.get("svcbAdoption").textContent,
        "Not measured for this web cohort",
    );
    assert.equal(
        elements.get("observationCount").textContent,
        `Showing ${formatNumber(observationCount)} of ${formatNumber(observationCount)} observations`,
    );

    const table = elements.get("observationsTable").innerHTML;
    assert.match(table, /badge-present/);
    assert.match(table, /badge-absent/);
    assert.match(table, />absent</);
    assert.doesNotMatch(table, /not_applicable/);

    const filter = elements.get("statusFilter");
    filter.value = "absent";
    filter.listeners.get("change")();
    assert.equal(
        elements.get("observationCount").textContent,
        `Showing ${formatNumber(absentCount)} of ${formatNumber(observationCount)} observations`,
    );

    filter.value = "all";
    const search = elements.get("domainSearch");
    search.value = "google.com";
    search.listeners.get("input")();
    const googleCount = currentLatest.observations.filter(
        (observation) => observation.domain === "google.com",
    ).length;
    assert.equal(
        elements.get("observationCount").textContent,
        `Showing ${formatNumber(googleCount)} of ${formatNumber(observationCount)} observations`,
    );
}

async function testEscaping() {
    const elements = await render(async (relativePath) => {
        if (!relativePath.endsWith("latest.json")) return jsonResponse(relativePath);
        return jsonResponse(relativePath, (latest) => {
            latest.observations[0].domain = "<script>alert(1)</script>";
            latest.observations[0].name = "<img src=x onerror=alert(1)>";
            return latest;
        });
    });
    const table = elements.get("observationsTable").innerHTML;
    assert.match(table, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.match(table, /&lt;img src=x onerror=alert\(1\)&gt;/);
    assert.doesNotMatch(table, /<script>alert\(1\)<\/script>/);
}

async function testPartialHistoryFailure() {
    const elements = await render(async (relativePath) => {
        if (relativePath.endsWith("changes.json")) return { ok: false, status: 404 };
        return jsonResponse(relativePath);
    });
    assert.equal(
        elements.get("httpsAdoptionValue").textContent,
        formatPercent(currentLatest.metrics.adoption.https.percentage),
    );
    assert.equal(elements.get("dataStatus").className, "alert alert-warning");
    assert.match(elements.get("changeContext").textContent, /change data is unavailable/);
}

async function main() {
    await testCurrentData();
    await testEscaping();
    await testPartialHistoryFailure();
    console.log("dashboard smoke tests passed");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
