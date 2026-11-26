import json
import tempfile
import unittest
from pathlib import Path

import httpx
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from firmware.cisco import Document, FAMILIES, parse_release_notes
from firmware.guidance import RECOMMENDED, SECURITY_FEED, feed_records, recommended_rows
from firmware.main import create_app
from firmware.monitor import recommend
from firmware.summary import GROQ_URL

NEXUS_PATH = "/c/en/us/td/docs/test/{suffix}.html"


class FirmwareTests(unittest.TestCase):
    def test_monitor_compare_and_restart(self):
        available = ["7"]
        groq_requests = []
        groq_available = True

        def respond(request):
            if str(request.url) == GROQ_URL:
                groq_requests.append(json.loads(request.content))
                self.assertEqual(request.headers["Authorization"], "Bearer test-key")
                if not groq_available:
                    return httpx.Response(429)
                content = json.dumps({
                    "overview": "보안 패치 릴리스입니다.",
                    "points": [{
                        "kind": "변경", "title": "보안 <수정>", "detail": "보안 수정만 포함됩니다.",
                        "evidence": [1],
                    }, {
                        "kind": "확인", "title": "기존 버전과 동일", "detail": "지원 범위가 동일합니다.",
                        "evidence": [1],
                    }],
                })
                return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})
            self.assertNotIn("Authorization", request.headers)
            if str(request.url) == RECOMMENDED["nexus"]:
                return httpx.Response(200, text="""
                    <table><tr><th>Hardware</th><th>Recommended Release Version</th></tr>
                    <tr><td>Nexus test platform</td><td>10.4(8)M</td></tr></table>
                """)
            if str(request.url) == SECURITY_FEED:
                return httpx.Response(200, text="""
                    <rss><channel><item><title>Official Cisco test advisory</title>
                    <link>https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-test-Abc</link>
                    <description>Security Impact Rating: High CVE: CVE-2026-12345</description>
                    </item></channel></rss>
                """)
            if str(request.url) == FAMILIES["nexus"][1]:
                links = "".join(
                    f'<a href="{NEXUS_PATH.format(suffix=n)}">'
                    f'Cisco Nexus 9000 Series NX-OS Release Notes, Release 10.4({n})M</a>'
                    for n in reversed(available)
                )
                return httpx.Response(200, text=links)
            suffix = request.url.path.rsplit("/", 1)[-1].split(".")[0]
            lines = {
                "7": "Original software capability.",
                "8": "This release contains only security fixes.",
                "9": "A later software feature.",
            }
            paragraph = lines[suffix]
            if suffix == "8":
                paragraph += " CVE-2026-12345"
                if "9" in available:
                    paragraph += "</p><p>Correction from Cisco."
            return httpx.Response(
                200, text=f'<div id="eot-doc-wrapper"><p class="pToC_Subhead1">Introduction</p><p>{paragraph}</p></div>',
            )

        transport = httpx.MockTransport(respond)
        with tempfile.TemporaryDirectory() as directory:
            database = f"sqlite:///{Path(directory) / 'firmware.sqlite3'}"
            app = create_app(database, poll_seconds=0, transport=transport, groq_key="test-key")
            with TestClient(app) as client:
                self.assertEqual(client.post("/api/nexus/scan").json()["versions"], ["10.4(7)M"])
                self.assertEqual(client.get("/api/nexus/events").json(), [])
                available.append("8")
                comparison = client.get(
                    "/api/nexus/compare", params={"before": "10.4(7)M", "after": "10.4(8)M"}
                )
                self.assertEqual(comparison.status_code, 200)
                self.assertEqual(comparison.json()["added"][0]["category"], "overview")
                guidance = comparison.json()["guidance"]
                self.assertEqual(guidance["security"]["to"]["advisories"][0]["severity"], "High")
                self.assertEqual(guidance["security"]["from"]["advisories"], [])
                self.assertEqual(guidance["recommendations"]["rows"][0]["versions"], ["10.4(8)M"])
                self.assertEqual(groq_requests, [])
                params = {"before": "10.4(7)M", "after": "10.4(8)M"}
                page = client.get("/", params=params).text
                self.assertIn("보안 패치 릴리스입니다.", page)
                self.assertIn("보안 &lt;수정&gt;", page)
                self.assertIn("목표 10.4(8)M · Cisco 권장", page)
                self.assertIn("Cisco High", page)
                self.assertIn("재부팅·트래픽", page)
                diff = BeautifulSoup(page, "html.parser").select_one("details.diff")
                self.assertIn("기준 10.4(7)M", diff.select_one(".diff-head").get_text(" ", strip=True))
                self.assertIn("목표 10.4(8)M", diff.select_one(".diff-head").get_text(" ", strip=True))
                self.assertIn("Original software capability.", diff.select_one(".diff-removed").get_text())
                self.assertIn("This release contains only security fixes.", diff.select_one(".diff-added").get_text())
                response = client.get("/api/nexus/compare", params={**params, "summarize": "true"})
                summary = response.json()["summary"]
                self.assertEqual(summary["status"], "ok")
                self.assertEqual(len(summary["points"]), 1)
                self.assertEqual(summary["points"][0]["sources"], ["https://www.cisco.com" + NEXUS_PATH.format(suffix="8")])
                self.assertEqual(len(groq_requests), 1)
                evidence = json.loads(groq_requests[0]["messages"][1]["content"])["evidence"]
                self.assertEqual([item["text"] for item in evidence], ["This release contains only security fixes. CVE-2026-12345"])
                groq_available = False
                fallback = client.get(
                    "/api/nexus/compare", params={"before": params["after"], "after": params["before"], "summarize": "true"}
                )
                self.assertEqual(fallback.status_code, 200)
                self.assertEqual(fallback.json()["summary"]["status"], "unavailable")
                self.assertTrue(fallback.json()["added"])
                client.post("/api/nexus/scan")
                result = client.get("/api/nexus/events").json()
                self.assertEqual(result[0]["kind"], "new_release")
                self.assertEqual(result[0]["recommendation"]["grade"], "필요")
                available.append("9")
                client.post("/api/nexus/scan")
                result = client.get("/api/nexus/events").json()
                self.assertEqual([e["kind"] for e in result], ["new_release", "document_revision", "new_release"])
                client.post("/api/nexus/scan")
                self.assertEqual(len(client.get("/api/nexus/events").json()), 3)
                self.assertIn("문서 개정", client.get("/").text)
                self.assertEqual(client.get("/api/catalyst/compare", params={"before": "bad", "after": "2"}).status_code, 422)
            with TestClient(create_app(database, poll_seconds=0, transport=transport)) as client:
                self.assertEqual(len(client.get("/api/nexus/events").json()), 3)

    def test_cisco_guidance_scopes_versions_and_advisory_ids(self):
        rows = recommended_rows("catalyst", """
            <table><tr><th>Product Family</th><th>Product Details</th><th>Recommended Cisco IOS XE release</th></tr>
            <tr><td rowspan="2">Catalyst 9300</td><td>9300L</td><td>17.18.4</td></tr>
            <tr><td>C9300X (all models)</td><td>17.15.6</td></tr>
            <tr><td>Catalyst 9400</td><td>C9400</td><td>17.18.5</td></tr></table>
        """)
        self.assertEqual([row["versions"] for row in rows], [["17.18.4"], ["17.15.6"]])
        records = feed_records("""<rss><channel><item><title>Informational notice</title>
            <link>https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-notice-Abc</link>
            <description>Refers to CVE-2026-12345. Security Impact Rating: Informational</description>
            </item></channel></rss>""")
        self.assertEqual(records, [])

    def test_bundled_versions_and_grade(self):
        url = "https://www.cisco.com/example.html"
        catalyst = parse_release_notes("catalyst", Document("17.18.x", url), """
            <main><article><h2>What's New in Cisco IOS XE 17.18.x</h2>
            <h3>Software Features in Cisco IOS XE 17.18.2</h3><p>New feature.</p>
            <h3>Software Features in Cisco IOS XE 17.18.1</h3><p>Earlier feature.</p>
            </article></main>""")
        self.assertEqual(set(catalyst["versions"]), {"17.18.1", "17.18.2"})
        ucs = parse_release_notes("ucs", Document("6.0(1)", url), """
            <main><article><h2>Revision History</h2>
            <table><tr><td>Created release notes for 6.0(1.250194).</td></tr></table>
            <h2 id="fix">Resolved Caveats in Release 6.0(1.250192)</h2>
            <p>A mandatory firmware update applies to affected models.</p>
            </article></main>""")
        self.assertEqual(set(ucs["versions"]), {"6.0(1.250194)", "6.0(1.250192)"})
        result = recommend(ucs["versions"]["6.0(1.250192)"])
        self.assertEqual(result["grade"], "필수")
        self.assertEqual(result["evidence"]["source"], url + "#fix")
        self.assertEqual(recommend([])["grade"], "판정 보류")
