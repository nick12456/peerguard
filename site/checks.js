// PeerGuard checks. Plain code finds every problem and decides the verdict.
// The AI only explains the report and may add findings, never remove them.
//
// Three checks:
//   works       - the site's public agent files load and pass the runtime's validation
//   leaks       - API keys or other secrets in those public files
//   manipulates - agent text that tries to steer a calling assistant
//
// Runs in the browser and in Node (tests). Every network call goes through fetchImpl.

import { parseHocon } from "./runtime/hocon.js";
import { AgentNetwork, validateNetwork } from "./runtime/kernel.js";

export const VERDICT = {
  SAFE: "Safe to connect",
  CAUTION: "Connect with caution",
  DONT: "Don't connect",
};

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const MAX_FILE_CHARS = 512 * 1024;
const MAX_NETWORKS = 3;
const MAX_TEXT_PER_AGENT = 6000;
const MAX_AI_FINDINGS = 10;

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

// Secrets. Values that look like placeholders are ignored.
const SECRET_RULES = [
  { label: "OpenAI or Anthropic style API key", re: /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}/g },
  { label: "AWS access key ID", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { label: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { label: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { label: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { label: "Private key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { label: "JSON Web Token", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { label: "Bearer token", re: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/g },
  { label: "Password inside a URL", re: /\bhttps?:\/\/[^\s/:@"']+:[^\s/@"']+@/g },
  {
    label: "Field named like a secret",
    re: /"(?:api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|access[_-]?token|auth[_-]?token|byok[_-]?key)"\s*:\s*"([^"]{8,})"/gi,
  },
];
const PLACEHOLDER = /^(?:<.*>|\$\{.*\}|\{.*\}|your[_ -]|x{4,}|\*{4,}|todo|changeme|example|placeholder|redacted)/i;

// Text that tries to steer a calling assistant. "error" blocks connecting, "warning" is
// worth a look. A rule with negationGuard is skipped when the match follows "never",
// "do not" and the like, so protective rules such as "never share your API key" pass.
const MANIPULATION_RULES = [
  {
    category: "Overrides the caller's rules",
    severity: "error",
    re: /\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your|their|the caller'?s?|system|other)\b[^.\n]{0,25}\b(?:instructions?|rules|prompts?|polic(?:y|ies)|guidelines|guardrails)\b/gi,
    negationGuard: true,
  },
  {
    category: "Overrides the caller's rules",
    severity: "error",
    re: /\byou are now\b|\bnew system (?:prompt|instructions?)\b|\b(?:developer|jailbreak|god) mode\b/gi,
  },
  {
    category: "Asks for keys or private data",
    severity: "error",
    // A directive verb, then "your", "the visitor's" and the like, then something private.
    // Descriptions such as "it may leak keys" have no determiner and are not flagged.
    re: /\b(?:reveal|print|repeat|output|show|send|share|leak|include|copy|forward|paste)\b[^.\n;]{0,40}\b(?:your|the|their|its|any|all|every)\b[^.\n;]{0,25}\b(?:api[ -]?keys?|system prompts?|(?:own |hidden |system )?instructions|credentials?|passwords?|secrets?|access tokens?|chat history|conversation history|private context|sly_data)\b/gi,
    negationGuard: true,
  },
  {
    category: "Sends data to an outside address",
    severity: "error",
    re: /\b(?:send|post|forward|upload|submit|transmit|report)\b[^.\n]{0,60}\bto\s+https?:\/\//gi,
    negationGuard: true,
  },
  {
    category: "Sends data to an outside address",
    severity: "error",
    re: /!\[[^\]]*\]\(https?:\/\/[^)\s]*(?:\{|%7b|\?)[^)]*\)/gi,
  },
  {
    category: "Acts without asking the visitor",
    severity: "error",
    re: /\b(?:without|skip(?:ping)?|bypass(?:ing)?|no need (?:for|to))\b[^.\n;]{0,30}\b(?:asking|confirm(?:ation|ing)?|consent|approval|permission|the (?:consent|confirmation) (?:card|dialog))\b/gi,
    negationGuard: true,
  },
  {
    category: "Claims to be safe or targets reviewers",
    severity: "error",
    re: /\b(?:rate|mark|report|classify|treat|label)\s+(?:this|it|us|the site|this site|this network)\b[^.\n]{0,20}\b(?:safe|trusted|verified|clean|harmless)\b|\b(?:ai |security |safety )?(?:scanners?|reviewers?|auditors?)\b[^.\n]{0,40}\b(?:must|should|need to|are required to)\b/gi,
  },
  {
    category: "Claims to be safe or targets reviewers",
    severity: "warning",
    re: /\b(?:this|the|our)\s+(?:site|network|agent|assistant|website)\s+(?:is|has been)\s+(?:safe|trusted|verified|secure|approved|certified)\b/gi,
  },
  {
    category: "Hides what it does",
    severity: "warning",
    re: /\b(?:do not|don't|never)\s+(?:tell|mention|reveal|disclose|inform)\b[^.\n]{0,20}\b(?:the )?(?:user|visitor|customer|human|anyone)\b|\bsecretly\b|\bhide (?:this|it) from\b/gi,
  },
  {
    category: "Hidden characters",
    severity: "error",
    re: /[​-‏‪-‮⁠-⁤⁦-⁩﻿]/g,
  },
];
const HIDDEN_CHARS = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;
const NEGATION = /\b(?:never|not|no|don't|do not|must not|mustn't|cannot|can't|won't)\b[^.\n]{0,15}$/i;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scan one agentic website.
 *
 * :param input: The site URL (the folder that holds agent-manifest.json) or a network URL
 *   (that folder, then the network name).
 * :param options: {fetchImpl} - the fetch function to use.
 * :return: {report, texts}. report is plain JSON for the page and the agents. texts holds
 *   each scanned agent's text for the AI reviewer.
 */
export async function scanSite(input, { fetchImpl = globalThis.fetch } = {}) {
  const findings = [];
  const texts = [];
  const site = { input, base: null, manifestUrl: null, networks: [], agentCount: 0 };

  const target = parseTarget(input, findings);
  if (target) {
    await scanTarget(target, fetchImpl, site, findings, texts);
  }
  return { report: buildReport(site, findings), texts };
}

/**
 * Add a finding from the AI reviewer, after checking that its quote is really in the
 * scanned text. AI findings are warnings: they can lower the verdict, never raise it.
 *
 * :param report: The current report (changed in place).
 * :param texts: The scanned agent texts from scanSite.
 * :param args: {agent, category, quote, reason}.
 * :return: {ok: true, report} or {ok: false, reason}.
 */
export function addReviewFinding(report, texts, args) {
  if (!report || !texts?.length) {
    return { ok: false, reason: "No scanned agent text to review. Scan a site first." };
  }
  const source = texts.find((t) => t.agent === args.agent);
  if (!source) {
    return { ok: false, reason: `No agent named "${args.agent}" in the scan. Use a name from website_get_scanned_text.` };
  }
  const quote = normalize(args.quote);
  if (quote.length < 8) {
    return { ok: false, reason: "The quote is too short. Copy at least a few words exactly." };
  }
  if (!normalize(source.text).includes(quote)) {
    return { ok: false, reason: `That quote is not in ${args.agent}'s text. Copy the exact words, or drop the finding.` };
  }
  const aiCount = report.findings.filter((f) => f.source === "ai").length;
  if (aiCount >= MAX_AI_FINDINGS) {
    return { ok: false, reason: `The report already has ${MAX_AI_FINDINGS} AI findings.` };
  }
  if (report.findings.some((f) => f.source === "ai" && normalize(f.evidence) === quote)) {
    return { ok: true, report };
  }
  report.findings.push({
    check: "manipulates",
    severity: "warning",
    source: "ai",
    title: `AI reviewer: ${args.category}`,
    detail: args.reason,
    fix: "Remove or rewrite this text so it only describes what this site offers.",
    where: `${source.where}`,
    evidence: args.quote.slice(0, 200),
  });
  Object.assign(report, summarize(report.findings));
  return { ok: true, report };
}

/**
 * Decide the verdict from the findings alone.
 *
 * :param findings: The list of findings.
 * :return: One of the VERDICT values.
 */
export function decideVerdict(findings) {
  if (findings.some((f) => f.severity === "error")) {
    return VERDICT.DONT;
  }
  if (findings.some((f) => f.severity === "warning")) {
    return VERDICT.CAUTION;
  }
  return VERDICT.SAFE;
}

// ---------------------------------------------------------------------------
// Works
// ---------------------------------------------------------------------------

function parseTarget(input, findings) {
  let url;
  try {
    url = new URL(String(input).trim());
  } catch {
    findings.push(works("error", "Not a full URL", "Give the full address, starting with https://.", "Paste the site URL, such as https://example.netlify.app/."));
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    findings.push(works("error", "Not a web address", `${url.protocol} is not http or https.`, "Use an https:// address."));
    return null;
  }
  if (url.protocol === "http:") {
    if (LOCAL_HOSTS.has(url.hostname)) {
      findings.push(works("warning", "Local address over http", "Fine for testing on your machine. Callers on the internet cannot reach it.", "Host the site over https before you share it."));
    } else {
      findings.push(works("error", "Not served over https", "The spec requires https for every host except localhost.", "Serve the site over https."));
      return null;
    }
  }
  url.hash = "";
  url.search = "";
  return url;
}

// Try the address as a network URL (folder + network name) first, then as a folder.
function candidates(url) {
  if (url.pathname.endsWith("/agent-manifest.json")) {
    return [{ base: new URL("./", url).href, network: null }];
  }
  const list = [];
  const segments = url.pathname.split("/").filter(Boolean);
  const last = segments.at(-1);
  if (last && !url.pathname.endsWith("/") && !last.includes(".")) {
    list.push({ base: new URL("./", url).href, network: decodeURIComponent(last) });
  }
  list.push({ base: url.href.endsWith("/") ? url.href : `${url.href}/`, network: null });
  return list;
}

async function scanTarget(url, fetchImpl, site, findings, texts) {
  // 1. Find agent-manifest.json.
  let found = null;
  const misses = [];
  for (const candidate of candidates(url)) {
    const manifestUrl = new URL("agent-manifest.json", candidate.base).href;
    const file = await load(manifestUrl, fetchImpl);
    if (file.ok) {
      found = { ...candidate, manifestUrl, file };
      break;
    }
    misses.push({ manifestUrl, file });
  }
  if (!found) {
    const unreachable = misses.every((m) => m.file.unreachable);
    findings.push(works(
      "error",
      "No agent-manifest.json found",
      unreachable
        ? `Could not load ${misses.map((m) => m.manifestUrl).join(" or ")}. The site may be down, the URL may be wrong, or the file is not served with the Access-Control-Allow-Origin header browsers need.`
        : `Tried ${misses.map((m) => `${m.manifestUrl} (${m.file.status || m.file.problem})`).join(" and ")}.`,
      "Publish agent-manifest.json in the site folder and serve it with Access-Control-Allow-Origin: *.",
    ));
    return;
  }
  site.base = found.base;
  site.manifestUrl = found.manifestUrl;
  noteRedirect(found.file, found.manifestUrl, "agent-manifest.json", findings);
  scanSecrets(found.file.text, "agent-manifest.json", findings);
  scanSecretKeysInJson(found.file.text, "agent-manifest.json", findings);

  // 2. Read the manifest.
  let manifest;
  try {
    manifest = JSON.parse(found.file.text);
  } catch (error) {
    findings.push(works("error", "Manifest is not valid JSON", `${found.manifestUrl}: ${error.message}`, "Fix the JSON syntax in agent-manifest.json."));
    return;
  }
  const entries = Array.isArray(manifest?.networks) ? manifest.networks : [];
  if (!entries.length) {
    findings.push(works("error", "Manifest lists no networks", "agent-manifest.json has no \"networks\" list.", "Add a networks entry with name, front_man and hocon."));
    return;
  }
  for (const entry of entries) {
    if (typeof entry?.description === "string") {
      scanManipulation(entry.description, `agent-manifest.json → ${entry.name || "network"} description`, findings);
    }
  }

  // 3. Pick the networks to scan.
  let chosen = entries;
  if (found.network) {
    chosen = entries.filter((e) => e?.name === found.network);
    if (!chosen.length) {
      findings.push(works(
        "error",
        "No network with that name",
        `The manifest lists ${entries.map((e) => e?.name).filter(Boolean).join(", ") || "none"}, not "${found.network}". A caller never runs a different network.`,
        "Use the exact network name from agent-manifest.json in the URL.",
      ));
      return;
    }
  }
  for (const entry of chosen.slice(0, MAX_NETWORKS)) {
    await scanNetwork(entry, found.base, fetchImpl, site, findings, texts);
  }
}

async function scanNetwork(entry, base, fetchImpl, site, findings, texts) {
  const name = entry?.name;
  if (typeof name !== "string" || typeof entry.front_man !== "string" || typeof entry.hocon !== "string") {
    findings.push(works("error", "Incomplete network entry", "Each network in the manifest needs name, front_man and hocon.", "Fill in all three fields."));
    return;
  }
  const networkUrl = new URL(entry.hocon, base).href;
  if (new URL(networkUrl).origin !== new URL(base).origin) {
    findings.push(works("warning", "Network file on another site", `${name} loads its agents from ${networkUrl}. That other site decides what the agents are told.`, "Host the network file on the same site as the manifest."));
  }
  const file = await load(networkUrl, fetchImpl);
  if (!file.ok) {
    findings.push(works(
      "error",
      "Network file does not load",
      file.unreachable
        ? `Could not load ${networkUrl}. It may be missing or lack the Access-Control-Allow-Origin header.`
        : `${networkUrl} answered ${file.status || file.problem}.`,
      "Publish the network file named in the manifest's \"hocon\" field and serve it with Access-Control-Allow-Origin: *.",
    ));
    return;
  }
  noteRedirect(file, networkUrl, `${name} network file`, findings);
  const fileLabel = networkUrl.split("/").pop();
  scanSecrets(file.text, fileLabel, findings);
  scanSecretKeysInJson(file.text, fileLabel, findings);

  let config;
  try {
    config = parseHocon(file.text);
  } catch (error) {
    findings.push(works("error", "Network file does not parse", `${fileLabel}: ${error.message}`, "Rebuild the network file from its HOCON source."));
    return;
  }
  const network = new AgentNetwork(config, name);
  const { errors } = validateNetwork(network);
  for (const message of errors) {
    findings.push(works("error", "Network fails validation", message, "Fix the HOCON and rebuild. Callers refuse a network that fails validation."));
  }
  if (!network.getAgentSpec(entry.front_man)) {
    findings.push(works("error", "Front agent missing", `The manifest's front_man "${entry.front_man}" is not an agent in ${fileLabel}.`, "Make front_man match the front agent's name."));
  }

  const agents = (config.tools || []).filter((a) => a && typeof a.name === "string");
  site.networks.push({ name, frontMan: entry.front_man, networkUrl, agents: agents.map((a) => a.name) });
  site.agentCount += agents.length;

  // Shared text is pasted into instructions, so scan it too.
  const shared = config.commondefs?.replacement_strings || {};
  for (const [key, value] of Object.entries(shared)) {
    if (typeof value === "string") {
      scanManipulation(value, `${fileLabel} → shared text "${key}"`, findings);
    }
  }
  if (typeof config.metadata?.description === "string") {
    scanManipulation(config.metadata.description, `${fileLabel} → description`, findings);
  }
  for (const agent of agents) {
    const where = `${fileLabel} → agent ${agent.name}`;
    const text = [agent.function?.description, agent.instructions]
      .filter((t) => typeof t === "string")
      .join("\n\n");
    scanManipulation(text, where, findings);
    const expanded = expandShared(text, shared);
    texts.push({ agent: agent.name, network: name, where, text: expanded.slice(0, MAX_TEXT_PER_AGENT) });
  }
}

async function load(url, fetchImpl) {
  let response;
  try {
    // Public agent files never need the visitor's cookies.
    response = await fetchImpl(url, { credentials: "omit", cache: "no-store", redirect: "follow" });
  } catch (error) {
    return { ok: false, unreachable: true, problem: String(error?.message || error) };
  }
  let text = "";
  try {
    text = await response.text();
  } catch (error) {
    return { ok: false, status: response.status, problem: "unreadable body" };
  }
  if (text.length > MAX_FILE_CHARS) {
    return { ok: false, status: response.status, problem: `larger than ${MAX_FILE_CHARS / 1024} KB` };
  }
  return {
    ok: response.ok,
    status: response.status,
    problem: response.ok ? null : `HTTP ${response.status}`,
    text,
    finalUrl: response.url || url,
    redirected: Boolean(response.redirected),
  };
}

function noteRedirect(file, requested, label, findings) {
  if (!file.redirected || !file.finalUrl) {
    return;
  }
  if (new URL(file.finalUrl).origin !== new URL(requested).origin) {
    findings.push(works("warning", "Redirects to another site", `${label} redirects to ${file.finalUrl}.`, "Serve the file directly from the site's own address."));
  }
}

// ---------------------------------------------------------------------------
// Leaks
// ---------------------------------------------------------------------------

function scanSecrets(text, where, findings) {
  for (const rule of SECRET_RULES) {
    if (rule.label === "Field named like a secret") {
      continue;
    }
    for (const match of text.matchAll(rule.re)) {
      findings.push({
        check: "leaks",
        severity: "error",
        source: "code",
        title: rule.label,
        detail: "Anyone can read this file, so anyone can copy this secret.",
        fix: "Delete it from the file, then revoke it with its provider and issue a new one. Keys belong in the visitor's AI model settings, never in published files.",
        where,
        evidence: mask(match[0]),
      });
    }
  }
}

function scanSecretKeysInJson(text, where, findings) {
  const rule = SECRET_RULES.find((r) => r.label === "Field named like a secret");
  for (const match of text.matchAll(rule.re)) {
    const value = match[1];
    if (PLACEHOLDER.test(value) || /^https?:\/\//.test(value)) {
      continue;
    }
    // Skip a value already reported by a more specific rule.
    if (findings.some((f) => f.check === "leaks" && f.where === where && f.evidence === mask(value))) {
      continue;
    }
    findings.push({
      check: "leaks",
      severity: "error",
      source: "code",
      title: rule.label,
      detail: `The field ${match[0].split(":")[0]} holds a value that looks like a secret.`,
      fix: "Remove the value from the published file and revoke it with its provider.",
      where,
      evidence: mask(value),
    });
  }
}

function mask(secret) {
  const s = String(secret);
  return s.length <= 8 ? "••••" : `${s.slice(0, 6)}…(${s.length} characters)`;
}

// ---------------------------------------------------------------------------
// Manipulates
// ---------------------------------------------------------------------------

function scanManipulation(text, where, findings) {
  for (const rule of MANIPULATION_RULES) {
    for (const match of text.matchAll(rule.re)) {
      if (rule.negationGuard && NEGATION.test(text.slice(Math.max(0, match.index - 40), match.index))) {
        continue;
      }
      const hidden = rule.category === "Hidden characters";
      findings.push({
        check: "manipulates",
        severity: rule.severity,
        source: "code",
        title: rule.category,
        detail: hidden
          ? "Invisible or direction-changing characters can hide text from people while models still read it."
          : "A calling assistant may read this as an instruction to it.",
        fix: hidden
          ? "Remove the invisible characters."
          : "Remove or rewrite this text so it only describes what this site offers.",
        where,
        evidence: hidden ? `Character U+${match[0].codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}` : excerpt(text, match.index, match[0].length),
      });
    }
  }
}

function excerpt(text, index, length) {
  // Show the match with a few words either side, cut at word boundaries.
  let start = Math.max(0, index - 40);
  let end = Math.min(text.length, index + length + 40);
  if (start > 0) {
    const space = text.indexOf(" ", start);
    start = space >= 0 && space < index ? space + 1 : start;
  }
  if (end < text.length) {
    const space = text.lastIndexOf(" ", end);
    end = space > index + length ? space : end;
  }
  const shown = text.slice(start, end).replace(HIDDEN_CHARS, "[hidden]").replace(/\s+/g, " ").trim();
  return `${start > 0 ? "…" : ""}${shown}${end < text.length ? "…" : ""}`;
}

function expandShared(text, shared) {
  return text.replace(/\{([A-Za-z0-9_]+)\}/g, (whole, key) => (typeof shared[key] === "string" ? shared[key] : whole));
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

function works(severity, title, detail, fix) {
  return { check: "works", severity, source: "code", title, detail, fix, where: "", evidence: "" };
}

function summarize(findings) {
  const count = (check, severity) => findings.filter((f) => f.check === check && f.severity === severity).length;
  const counts = {};
  for (const check of ["works", "leaks", "manipulates"]) {
    counts[check] = { errors: count(check, "error"), warnings: count(check, "warning") };
  }
  const verdict = decideVerdict(findings);
  const errors = findings.filter((f) => f.severity === "error").length;
  const warnings = findings.filter((f) => f.severity === "warning").length;
  const summary = verdict === VERDICT.SAFE
    ? "These checks found no problems."
    : `${errors} problem${errors === 1 ? " blocks" : "s block"} connecting, ${warnings} to check.`;
  return { verdict, summary, counts };
}

function buildReport(site, findings) {
  return {
    scannedAt: new Date().toISOString(),
    site,
    findings,
    ...summarize(findings),
  };
}

function normalize(text) {
  return String(text || "").replace(/\s+/g, " ").trim().toLowerCase();
}
