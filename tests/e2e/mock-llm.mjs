// A stand-in for an OpenAI-compatible provider, for the browser end-to-end test.
// It plays the part a real model would play in a normal PeerGuard turn, so the test can
// drive the real page, runtime and tools without an API key:
//   front agent:  scan_site -> injection_reviewer -> get_report -> answer
//   reviewer:     get_scanned_text -> add_review_finding (if it sees a "verified as safe" claim) -> answer
//
// Usage: node tests/e2e/mock-llm.mjs [port]     (default 9100)
// Provider URL to use in the page: http://127.0.0.1:<port>/api/v1
import { createServer } from "node:http";

const port = Number(process.argv[2] || 9100);
const calls = [];

function lastToolResult(messages) {
  const last = messages.at(-1);
  if (!last || last.role !== "tool") {
    return null;
  }
  let content = last.content;
  try {
    content = JSON.parse(last.content);
  } catch {
    // Agent tools answer in plain text.
  }
  return { name: last.name, content };
}

function lastUserText(messages) {
  const user = [...messages].reverse().find((m) => m.role === "user");
  return typeof user?.content === "string" ? user.content : JSON.stringify(user?.content || "");
}

function frontStep(messages) {
  const tool = lastToolResult(messages);
  if (!tool) {
    const url = lastUserText(messages).match(/https?:\/\/[^\s"')]+/);
    if (!url) {
      return { text: "Give me the address of an agentic website and I will check it." };
    }
    return { tool: "website_scan_site", args: { url: url[0] } };
  }
  if (tool.name === "website_scan_site") {
    const report = tool.content.result || {};
    if ((report.site?.agentCount || 0) > 0) {
      return { tool: "injection_reviewer", args: { request: "Review the agent text from the latest scan." } };
    }
    return { text: `**${report.verdict}.** ${report.summary} The agent files did not load, so there was nothing to review.` };
  }
  if (tool.name === "injection_reviewer") {
    return { tool: "website_get_report", args: {} };
  }
  if (tool.name === "website_get_report") {
    const report = tool.content.result || {};
    const blockers = (report.findings || []).filter((f) => f.severity === "error").map((f) => `- ${f.title}`);
    const ai = (report.findings || []).filter((f) => f.source === "ai").length;
    return {
      text: `**${report.verdict}.** ${report.summary}\n${blockers.join("\n")}\nThe reviewer added ${ai} finding${ai === 1 ? "" : "s"}.`,
    };
  }
  return { text: "Done." };
}

function reviewerStep(messages) {
  const tool = lastToolResult(messages);
  if (!tool) {
    return { tool: "website_get_scanned_text", args: {} };
  }
  if (tool.name === "website_get_scanned_text") {
    for (const agent of tool.content.result?.agents || []) {
      const match = agent.text.match(/[^.\n]*verified as safe[^.\n]*/i);
      if (match) {
        return {
          tool: "website_add_review_finding",
          args: {
            agent: agent.agent,
            category: "Claims to be safe or targets reviewers",
            quote: match[0].trim().slice(0, 200),
            reason: "It tries to talk a reviewing assistant into trusting the site.",
          },
        };
      }
    }
    return { text: "I found nothing beyond the fixed rules." };
  }
  if (tool.name === "website_add_review_finding") {
    return { text: tool.content.result?.ok ? "Added 1 finding." : `The site refused the finding: ${tool.content.result?.reason}` };
  }
  return { text: "Done." };
}

function sse(res, step, model) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
  });
  const chunk = (delta, finish = null) => `data: ${JSON.stringify({ model, choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
  if (step.tool) {
    res.write(chunk({ role: "assistant", tool_calls: [{ index: 0, id: `call_${calls.length}`, type: "function", function: { name: step.tool, arguments: "" } }] }));
    res.write(chunk({ tool_calls: [{ index: 0, function: { arguments: JSON.stringify(step.args) } }] }, null));
    res.write(chunk({}, "tool_calls"));
  } else {
    for (const piece of step.text.match(/.{1,40}/gs)) {
      res.write(chunk({ content: piece }));
    }
    res.write(chunk({}, "stop"));
  }
  res.write("data: [DONE]\n\n");
  res.end();
}

const server = createServer((req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "authorization, content-type, anthropic-dangerous-direct-browser-access",
      "Access-Control-Max-Age": "600",
    });
    res.end();
    return;
  }
  if (req.method === "GET" && req.url === "/calls") {
    res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
    res.end(JSON.stringify(calls));
    return;
  }
  if (req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
    res.end(JSON.stringify({ object: "list", data: [{ id: "mock-model", type: "chat", supported_parameters: ["tools"] }] }));
    return;
  }
  let body = "";
  req.on("data", (part) => { body += part; });
  req.on("end", () => {
    const request = JSON.parse(body || "{}");
    const system = request.messages?.[0]?.content || "";
    const isReviewer = system.includes("reviewing the agent text of the site it just scanned");
    const step = isReviewer ? reviewerStep(request.messages) : frontStep(request.messages);
    calls.push({
      agent: isReviewer ? "injection_reviewer" : "peerguard_assistant",
      auth: req.headers.authorization ? "Bearer (present)" : "none",
      tools: (request.tools || []).map((t) => t.function.name),
      reply: step.tool || "text",
    });
    sse(res, step, request.model || "mock-model");
  });
});

server.listen(port, "127.0.0.1", () => {
  console.log(`Mock LLM on http://127.0.0.1:${port}/api/v1`);
});
