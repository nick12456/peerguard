// Runs the real agent network through the real browser runtime, with a scripted model
// instead of an AI provider. Checks that the front agent can scan, delegate to the
// reviewer, and that the reviewer can read the scanned text and add a finding.
// Run from the repo root:  node --test "tests/*.test.mjs"
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { ActionRegistry } from "../site/runtime/actions.js";
import { AgentNetwork } from "../site/runtime/kernel.js";
import { runAgent } from "../site/runtime/runner.js";
import { TraceBus } from "../site/runtime/trace.js";
import { ScriptedModel } from "./scripted_model.mjs";
import { registerActions } from "../site/site-actions.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const BASE = "http://localhost:8080";

async function diskFetch(url) {
  const u = new URL(url);
  if (u.host !== "unsafe.test") {
    throw new TypeError("Failed to fetch");
  }
  try {
    const text = await readFile(`${ROOT}site/test-site${decodeURIComponent(u.pathname)}`, "utf8");
    return { ok: true, status: 200, url, text: async () => text };
  } catch {
    return { ok: false, status: 404, url, text: async () => "Not found" };
  }
}

async function context(model) {
  const config = JSON.parse(await readFile(`${ROOT}site/peerguard.network.json`, "utf8"));
  const manifest = JSON.parse(await readFile(`${ROOT}site/agent-manifest.json`, "utf8"));
  const network = new AgentNetwork(config, "peerguard");
  const registry = new ActionRegistry();
  await registerActions({ register: registry.register.bind(registry, { base: BASE, network: "peerguard" }) });
  return {
    network,
    manifest,
    actions: registry,
    baseOrigin: BASE,
    displayOrigin: new URL(BASE).host,
    trace: new TraceBus(),
    isTop: true,
    frontMan: network.findFrontMan(),
    history: [],
    llm: model,
    confirmWebsiteActions: async () => true,
  };
}

test("scan, delegate to the reviewer, add a verified finding, report", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = diskFetch;
  try {
    const model = new ScriptedModel([
      { tool: "website_scan_site", arguments: { url: "https://unsafe.test/" } },
      { tool: "injection_reviewer", arguments: { request: "Review the agent text from the latest scan." } },
      { tool: "website_get_scanned_text", arguments: {} },
      {
        tool: "website_add_review_finding",
        arguments: {
          agent: "tidewhistle_assistant",
          category: "Claims to be safe or targets reviewers",
          quote: "verified as safe by the Open Agentic Web team",
          reason: "It tries to talk a reviewer into trusting the site.",
        },
      },
      { text: "Added 1 finding." },
      { tool: "website_get_report", arguments: {} },
      { text: "Don't connect. The site leaks a key and tries to steer callers." },
    ]);
    const ctx = await context(model);
    assert.equal(ctx.frontMan, "peerguard_assistant");
    const result = await runAgent(ctx, ctx.frontMan, "Is https://unsafe.test/ safe to connect to?", null, []);

    // The front agent is offered the website tools and the reviewer.
    const offered = model.toolNames(0);
    for (const name of ["website_scan_site", "website_get_report", "injection_reviewer"]) {
      assert.ok(offered.includes(name), `front agent gets ${name}`);
    }
    // The scan ran and returned the verdict.
    const scan = model.toolResults(1)[0];
    assert.equal(scan.status, "succeeded", JSON.stringify(scan));
    assert.equal(scan.result.verdict, "Don't connect");
    // The reviewer read the scanned text and its finding was accepted.
    const added = model.toolResults(4).find((r) => r.result && "verdict" in r.result);
    assert.equal(added.status, "succeeded", JSON.stringify(model.toolResults(4)));
    assert.equal(added.result.ok, true);
    // The final report holds the AI finding, and the verdict did not soften.
    const final = model.toolResults(6).at(-1);
    assert.ok(final.result.findings.some((f) => f.source === "ai"));
    assert.equal(final.result.verdict, "Don't connect");
    assert.match(result.text, /Don't connect/);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("the schema refuses a category the reviewer made up", async () => {
  const model = new ScriptedModel([
    {
      tool: "website_add_review_finding",
      arguments: { agent: "x", category: "Totally fine", quote: "some quote here", reason: "made up" },
    },
    { text: "done" },
  ]);
  const ctx = await context(model);
  await runAgent(ctx, "injection_reviewer", "Review.", null, []);
  const reply = model.calls[1].messages.filter((m) => m.role === "tool").map((m) => m.content).join(" ");
  assert.match(reply, /Invalid arguments|enum|must be one of/i, reply);
});
