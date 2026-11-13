"""Browser end-to-end test for PeerGuard.

Serves the site on three local origins, starts the mock LLM provider and drives the real
page in headless Chromium: scanning, the report, the assistant's settings panel and a full
chat turn through the real browser runtime.

Needs Python 3.10+, Node 22+ and Playwright:
    pip install playwright && python -m playwright install chromium
Run from the repo root:
    python tests/e2e/browser_e2e.py
Set CHROME_PATH to use an installed Chrome instead of Playwright's Chromium.
"""

import asyncio
import functools
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
TEST_SITE = SITE / "test-site"
PEERGUARD = "http://127.0.0.1:8080/"
UNSAFE = "http://localhost:8081/"
NO_CORS = "http://localhost:8082/"
MOCK_LLM = "http://127.0.0.1:9100/api/v1"

results = []


def check(name, ok, detail=""):
    results.append({"test": name, "ok": bool(ok), "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'}  {name}{'  - ' + detail if detail else ''}")


def serve(folder, port, cors):
    class Handler(SimpleHTTPRequestHandler):
        extensions_map = {
            **SimpleHTTPRequestHandler.extensions_map,
            ".js": "text/javascript",
            ".mjs": "text/javascript",
            ".json": "application/json",
            ".woff": "font/woff",
            ".svg": "image/svg+xml",
        }

        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            if cors:
                self.send_header("Access-Control-Allow-Origin", "*")
            super().end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), functools.partial(Handler, directory=str(folder)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


async def scan(page, url):
    before = await page.get_attribute("#report", "data-scanned-at") or ""
    await page.fill("#scan-url", url)
    await page.click("#scan-button")
    await page.wait_for_function(
        "(before) => !document.querySelector('#scan-button').disabled"
        " && (document.querySelector('#report').dataset.scannedAt || '') !== before",
        arg=before,
        timeout=20000,
    )


async def run():
    servers = [serve(SITE, 8080, True), serve(TEST_SITE, 8081, True), serve(TEST_SITE, 8082, False)]
    mock = subprocess.Popen(["node", str(ROOT / "tests/e2e/mock-llm.mjs"), "9100"], stdout=subprocess.PIPE)
    mock.stdout.readline()
    try:
        async with async_playwright() as p:
            launch = {"args": ["--no-sandbox"]}
            if os.environ.get("CHROME_PATH"):
                launch["executable_path"] = os.environ["CHROME_PATH"]
            browser = await p.chromium.launch(**launch)
            page = await browser.new_page(viewport={"width": 1280, "height": 900})
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))

            # 1. Page and assistant load.
            await page.goto(PEERGUARD, wait_until="networkidle")
            await page.wait_for_function("document.querySelector('#assistant-status').textContent.startsWith('Assistant')")
            status = await page.text_content("#assistant-status")
            check("page loads with no script errors", not errors, "; ".join(errors))
            check("assistant boots and asks for a key", "needs your AI provider key" in status, status)
            check("fonts are self-hosted and load", await page.evaluate(
                "document.fonts.ready.then(() => document.fonts.check('700 40px \"Big Shoulders\"'))"))

            # 2. PeerGuard scans itself (only the local-http note is expected locally).
            await page.click("button[data-example=self]")
            await page.wait_for_function("document.querySelector('#stamp-text').textContent !== 'Not checked'")
            await page.wait_for_function("!document.querySelector('#scan-button').disabled")
            titles = await page.eval_on_selector_all(".finding-title", "els => els.map(e => e.textContent)")
            check("PeerGuard passes its own scan", titles == ["Local address over http"], str(titles))

            # 3. The unsafe site, on another origin, is caught.
            await scan(page, UNSAFE)
            verdict = await page.text_content("#stamp-text")
            titles = await page.eval_on_selector_all(".finding-title", "els => els.map(e => e.textContent)")
            expected = {
                "OpenAI or Anthropic style API key",
                "Overrides the caller's rules",
                "Asks for keys or private data",
                "Acts without asking the visitor",
                "Claims to be safe or targets reviewers",
                "Hidden characters",
            }
            check("unsafe site gets Don't connect", verdict == "Don't connect", verdict)
            check("unsafe site: every planted problem is shown", expected <= set(titles), str(sorted(set(titles))))
            page_text = await page.text_content("body")
            check("the leaked key is masked on the page", "FAKE-DEMO-KEY" not in page_text)

            # 4. A site without the CORS header.
            await scan(page, NO_CORS)
            titles = await page.eval_on_selector_all(".finding-title", "els => els.map(e => e.textContent)")
            states = await page.eval_on_selector_all(".check-state", "els => els.map(e => e.textContent)")
            check("site without CORS is reported as not loading", "No agent-manifest.json found" in titles, str(titles))
            check("leak and manipulation checks are marked skipped", states[1:] == ["Not checked", "Not checked"], str(states))

            # 5. Bad input.
            await page.fill("#scan-url", "")
            await page.click("#scan-button")
            await page.wait_for_timeout(300)
            message = await page.text_content("#scan-status")
            check("empty input explains what to enter", "starting with https://" in message, message)

            # 6. Keyboard: Enter in the field runs a check.
            await page.fill("#scan-url", UNSAFE)
            await page.focus("#scan-url")
            before = await page.get_attribute("#report", "data-scanned-at")
            await page.keyboard.press("Enter")
            await page.wait_for_function("(b) => document.querySelector('#report').dataset.scannedAt !== b", arg=before)
            check("Enter key runs a check", True)

            # 7. Full chat turn through the real runtime, against the mock provider.
            await page.fill("#ns-key", "test-key-not-real")
            await page.evaluate("document.querySelector('.ns-settings-advanced').open = true")
            await page.fill("#ns-model", "mock-model")
            await page.fill("#ns-router", MOCK_LLM)
            await page.click("#ns-apply")
            await page.wait_for_timeout(500)
            await page.fill("#ns-input", f"Is {UNSAFE} safe to connect to?")
            await page.click("#ns-send")
            await page.wait_for_function(
                "[...document.querySelectorAll('#ns-msgs .ns-msg.bot')].some(m => m.textContent.includes('The reviewer added'))",
                timeout=60000,
            )
            reply = await page.evaluate("[...document.querySelectorAll('#ns-msgs .ns-msg.bot')].at(-1).textContent")
            check("chat answers with the verdict", "Don't connect" in reply, reply[:160])
            check("reviewer's finding was accepted", "The reviewer added 1 finding" in reply, reply[-60:])
            tags = await page.eval_on_selector_all(".finding .tag", "els => els.map(e => e.textContent)")
            check("AI finding appears in the report", "AI review" in tags, str(tags))
            check("verdict stays Don't connect after the AI review", await page.text_content("#stamp-text") == "Don't connect")
            calls = json.loads(urllib.request.urlopen("http://127.0.0.1:9100/calls").read())
            sequence = [f"{c['agent']}:{c['reply']}" for c in calls]
            check("agents ran in the expected order", sequence == [
                "peerguard_assistant:website_scan_site",
                "peerguard_assistant:injection_reviewer",
                "injection_reviewer:website_get_scanned_text",
                "injection_reviewer:website_add_review_finding",
                "injection_reviewer:text",
                "peerguard_assistant:website_get_report",
                "peerguard_assistant:text",
            ], " -> ".join(sequence))
            check("key is sent only as a bearer header to the provider", all(c["auth"] == "Bearer (present)" for c in calls))
            check("no script errors during the whole run", not errors, "; ".join(errors))
            shots = ROOT / "tests/e2e/screenshots"
            shots.mkdir(exist_ok=True)
            await page.locator("#report").screenshot(path=str(shots / "report.png"))
            await page.locator("#assistant").screenshot(path=str(shots / "chat.png"))

            # 8. Phone layout.
            phone = await browser.new_page(viewport={"width": 375, "height": 812})
            await phone.goto(PEERGUARD, wait_until="networkidle")
            await phone.click("button[data-example=self]")
            await phone.wait_for_function("document.querySelector('#stamp-text').textContent !== 'Not checked'")
            overflow = await phone.evaluate("document.documentElement.scrollWidth - window.innerWidth")
            check("no sideways scrolling on a 375px phone", overflow <= 0, f"{overflow}px")

            await browser.close()
    finally:
        mock.terminate()
        for server in servers:
            server.shutdown()

    passed = sum(r["ok"] for r in results)
    print(f"\n{passed}/{len(results)} browser checks passed")
    (ROOT / "tests/e2e/last-run.json").write_text(json.dumps({"ran": time.strftime("%Y-%m-%d %H:%M:%S"), "results": results}, indent=2))
    return passed == len(results)


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
