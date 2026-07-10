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
        bootstrap: {
            Modal: {
                getOrCreateInstance: () => ({ show() {} }),
            },
        },
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

function inspectObservation(elements, index = 0) {
    elements.get("observationsTable").listeners.get("click")({
        target: {
            closest(selector) {
                assert.equal(selector, ".observation-detail");
                return { dataset: { index: String(index) } };
            },
        },
    });
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

async function testWireEvidenceSummary() {
    const wirePayload = "AQIDBAUGBwgJCgsMDQ4PEA==";
    const nestedWirePayload = "bmVzdGVkLXdpcmUtcGF5bG9hZA==";
    let latestFixture;
    const elements = await render(async (relativePath) => {
        if (!relativePath.endsWith("latest.json")) return jsonResponse(relativePath);
        return jsonResponse(relativePath, (latest) => {
            latest.observations[0].wire_capture = {
                format_version: 1,
                responses: [
                    {
                        response_index: 0,
                        transport: "udp",
                        used_for_observation: false,
                        message: { encoding: "base64", value: "unused-payload", length: 64, sha256: "unused-hash" },
                    },
                    {
                        response_index: 1,
                        transport: "tcp",
                        used_for_observation: true,
                        message: { encoding: "base64", value: wirePayload, length: 128, sha256: "abc123def456" },
                    },
                ],
                unavailable_reason: null,
            };
            latest.observations[0].resolved_rrsets = [
                {
                    name: "alias.example.",
                    wire_capture: {
                        responses: [
                            {
                                response_index: 0,
                                message: {
                                    encoding: "base64",
                                    value: nestedWirePayload,
                                    length: 19,
                                    sha256: "nested-hash",
                                },
                            },
                        ],
                    },
                },
            ];
            latest.observations[0].wire_validation = {
                format_version: 1,
                status: "failed",
                responses: [
                    { response_index: 1, issues: [{ code: "svcparam_key_order" }, { code: "rdata_bounds" }] },
                ],
            };
            latestFixture = latest;
            return latest;
        });
    });

    inspectObservation(elements);
    const modal = elements.get("modalBody").innerHTML;
    const retainedJson = elements.get("observationJson").textContent;
    assert.match(modal, /<details class="wire-evidence mb-3">/);
    assert.doesNotMatch(modal, /<details[^>]+open/);
    assert.match(modal, />Captured</);
    assert.match(modal, />Failed</);
    assert.match(modal, />2</);
    assert.match(modal, />TCP</);
    assert.match(modal, /128 bytes/);
    assert.match(modal, /abc123def456/);
    assert.match(modal, /rdata_bounds/);
    assert.match(modal, /svcparam_key_order/);
    assert.doesNotMatch(modal, new RegExp(wirePayload));
    assert.doesNotMatch(retainedJson, new RegExp(wirePayload));
    assert.doesNotMatch(retainedJson, new RegExp(nestedWirePayload));
    assert.doesNotMatch(retainedJson, /unused-payload/);
    assert.match(retainedJson, /\[binary payload omitted\]/);
    assert.equal(
        latestFixture.observations[0].resolved_rrsets[0].wire_capture.responses[0].message.value,
        nestedWirePayload,
    );
}

async function testOldObservationWithoutWireEvidence() {
    const elements = await render(async (relativePath) => {
        if (!relativePath.endsWith("latest.json")) return jsonResponse(relativePath);
        return jsonResponse(relativePath, (latest) => {
            latest.observations = [{
                schema_version: 2,
                probe_type: "dns",
                domain: "legacy.example",
                full_domain: "legacy.example",
                record_type: "HTTPS",
                query_status: "no_answer",
                has_record: false,
                records: [],
            }];
            return latest;
        });
    });
    inspectObservation(elements);
    const modal = elements.get("modalBody").innerHTML;
    assert.match(modal, />Not collected</);
    assert.match(modal, />Not assessed</);
    assert.match(modal, /Binary payloads are intentionally omitted/);
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
    await testWireEvidenceSummary();
    await testOldObservationWithoutWireEvidence();
    await testPartialHistoryFailure();
    console.log("dashboard smoke tests passed");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
