import asyncio
import re
from time import monotonic
from urllib.parse import urlsplit
from xml.etree import ElementTree

import httpx
from bs4 import BeautifulSoup

from firmware.cisco import FAMILIES, ORIGIN, VERSION, get_text

RECOMMENDED = {
    "nexus": ORIGIN + "/c/en/us/td/docs/switches/datacenter/nexus9000/sw/recommended_release/"
    "b_Minimum_and_Recommended_Cisco_NX-OS_Releases_for_Cisco_Nexus_9000_Series_Switches.html",
    "catalyst": ORIGIN + "/c/en/us/support/docs/switches/catalyst-9300-series-switches/"
    "214814-recommended-releases-for-catalyst-9200-9.html",
}
PSIRT = "https://sec.cloudapps.cisco.com/security/center"
SECURITY_FEED = PSIRT + "/psirtrss10/CiscoSecurityAdvisory.xml"
SECURITY_LOOKUP = {
    "nexus": PSIRT + "/softwarechecker.x",
    "catalyst": PSIRT + "/softwarechecker.x",
    "ucs": PSIRT + "/publicationListing.x",
}
INSTALL_GUIDES = {
    "nexus": (
        ("재부팅·트래픽", "일반 업그레이드는 트래픽 중단을 수반합니다. ISSU 지원 여부는 모델·현재 버전·목표 버전과 구성 조건을 대조하세요.",
         ORIGIN + "/c/dam/en/us/td/docs/dcn/tools/nexus-9k3k-issu-matrix/index.html"),
        ("USB", "ISSU 매트릭스는 업그레이드 경로를 안내합니다. USB 사용 가능 여부는 선택한 장비와 작업 방식의 가이드에서 확인하세요.",
         FAMILIES["nexus"][1]),
    ),
    "catalyst": (
        ("재부팅·설치 방식", "일반 Install Mode 절차는 이미지 활성화 시 스위치 reload를 요구합니다. 실제 적용 절차는 현재 모드와 버전 경로를 확인하세요.",
         ORIGIN + "/c/en/us/support/docs/switches/catalyst-9300-series-switches/222280-upgrading-catalyst-9300-switches.html"),
        ("USB", "이 가이드의 USB는 이미지를 스위치 플래시로 옮기는 방법 중 하나입니다. TFTP 전송 절차도 제공합니다.",
         ORIGIN + "/c/en/us/support/docs/switches/catalyst-9300-series-switches/222280-upgrading-catalyst-9300-switches.html"),
    ),
    "ucs": (
        ("HUU · 호스트 재시작", "Cisco HUU 4.3 가이드는 호스트를 다시 시작해 HUU ISO로 부팅하는 절차를 제공합니다. 물리 USB 또는 CIMC/vKVM 가상 미디어를 사용할 수 있는지는 해당 모델·릴리스에서 확인하세요.",
         ORIGIN + "/c/en/us/td/docs/unified_computing/ucs/c/sw/lomug/4-3/"
         "b_cisco-host-upgrade-utility-user-guide-4-3/m-launching-ucs-huu-4-3.html"),
        ("CIMC · 관리 컨트롤러 재부팅", "IMC 6.0 가이드에서는 CIMC 펌웨어 활성화 시 BMC가 재부팅되어 관리 세션이 끊깁니다. 별도로 설명된 BIOS 설치 절차에는 호스트 전원 종료가 포함됩니다.",
         ORIGIN + "/c/en/us/td/docs/unified_computing/ucs/c/sw/cli/config/guide/6-0/"
         "b-cisco-ucs-c-series-servers-imc-cli-configuration-guide--release-6-0/m_cli_cimc_firmware_management.html"),
    ),
}
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
RATINGS = ("Critical", "High", "Medium", "Low", "Informational")
SIR = re.compile(r"Security Impact Rating\s*:\s*(" + "|".join(RATINGS) + r")\b", re.I)
INSTALL_SIGNAL = re.compile(r"\b(?:reboots?|reloads?|power[- ]cycl\w*|USB|virtual media|ISSU|intermediate (?:release|version))\b", re.I)
SECURITY_FIX = re.compile(r"\b(?:security (?:fixes|patches)|security hardening)\b", re.I)
NO_SECURITY_FIX = re.compile(r"\b(?:no (?:new )?security (?:fixes|patches)|does not (?:include|contain).{0,80}security fixes)\b", re.I)


def recommended_rows(family, html):
    soup = BeautifulSoup(html, "html.parser")
    for table in soup.find_all("table"):
        rows = table.find_all("tr")
        if not rows or "recommended" not in get_text(rows[0]).lower():
            continue
        result = []
        for row in rows[1:]:
            cells = [get_text(cell) for cell in row.find_all(["td", "th"], recursive=False)]
            if len(cells) < 2:
                continue
            if family == "catalyst" and not re.search(r"\bC?9300(?:LM|L|X)?\b|Catalyst 9300\b", " ".join(cells[:-1]), re.I):
                continue
            versions = VERSION[family].findall(cells[-1])
            if versions:
                result.append({"versions": versions, "condition": " · ".join(cells[:-1])})
        if result:
            return result
    raise ValueError("Cisco 권장 릴리스 표를 읽지 못했습니다.")


def advisory_url(url):
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.netloc not in {"www.cisco.com", "sec.cloudapps.cisco.com", "tools.cisco.com"}:
        return None
    slug = parts.path.rsplit("/", 1)[-1].removesuffix(".html")
    if re.fullmatch(r"cisco-sa-[A-Za-z0-9-]+", slug):
        return PSIRT + "/content/CiscoSecurityAdvisory/" + slug
    return None


def advisory_record(text, title, url, rss=False):
    rating = SIR.search(text)
    if not rating and not rss:
        rating = re.search(r"\b(" + "|".join(RATINGS) + r")\s+Advisory ID\s*:", text, re.I)
    if not rating:
        return None
    # RSS notices can quote other advisories. Use the entry's own CVE footer.
    cves = re.findall(r"\bCVE\s*:\s*((?:CVE-\d{4}-\d{4,}[,\s]*)+)", text, re.I) if rss else [text]
    score = re.search(r"CVSS Score\s*:\s*Base\s+(\d+(?:\.\d+)?)", text, re.I) if not rss else None
    return {
        "title": title, "source": url, "severity": rating[1].capitalize(),
        "cvss": score[1] if score else None,
        "cves": sorted({value.upper() for entry in cves for value in CVE.findall(entry)}),
    }


def feed_records(xml):
    root = ElementTree.fromstring(xml)
    records = []
    for item in root.iter():
        if item.tag.rsplit("}", 1)[-1] != "item":
            continue
        fields = {child.tag.rsplit("}", 1)[-1]: child.text or "" for child in item}
        url = advisory_url(fields.get("link", ""))
        if url:
            text = get_text(BeautifulSoup(fields.get("description", ""), "html.parser"))
            record = advisory_record(text, fields.get("title", ""), url, rss=True)
            if record and record["cves"]:
                records.append(record)
    return records


class CiscoGuidance:
    def __init__(self, client):
        self.client = client
        self.cache = {}
        self.pending = {}

    async def _fetch(self, url, parse):
        try:
            response = await self.client.get(url, timeout=5)
            response.raise_for_status()
            result = await asyncio.to_thread(parse, response.text)
        except (httpx.HTTPError, ValueError, ElementTree.ParseError):
            result = None
        self.cache[url] = (monotonic() + (3600 if result is not None else 120), result)
        return result

    async def fetch(self, url, parse):
        expires, value = self.cache.get(url, (0, None))
        if monotonic() < expires:
            return value
        task = self.pending.get(url)
        if task is None:
            task = asyncio.create_task(self._fetch(url, parse))
            self.pending[url] = task
            task.add_done_callback(lambda _: self.pending.pop(url, None))
        return await asyncio.shield(task)

    async def recommendations(self, family):
        url = RECOMMENDED.get(family)
        rows = await self.fetch(url, lambda html: recommended_rows(family, html)) if url else None
        return {"source": url or FAMILIES[family][1], "rows": rows, "available": bool(url)}

    async def security(self, family, target):
        items = target["items"]
        cves = sorted({cve.upper() for item in items for cve in CVE.findall(item["text"])})
        links = list(dict.fromkeys(
            url for item in items if item["category"] in {"security", "overview", "history", "fixed"}
            for href in item.get("references", ()) if (url := advisory_url(href))
        ))
        notices = list(dict.fromkeys(
            href for item in items for href in item.get("references", ())
            if href.startswith(ORIGIN + "/c/en/us/support/docs/field-notices/")
        ))
        fix = next((
            item for item in items
            if (item["category"] == "security" or SECURITY_FIX.search(item["text"]))
            and not NO_SECURITY_FIX.search(item["text"])
        ), None)

        async def detail(url):
            def parse(html):
                page = BeautifulSoup(html, "html.parser")
                title = next((get_text(h) for h in page.find_all("h1")
                              if get_text(h).lower() not in {"", "cisco security advisory"}), "Cisco 보안 공지")
                return advisory_record(get_text(page), title, url)
            return await self.fetch(url, parse)

        records = []
        if cves or links:
            feed, *details = await asyncio.gather(
                self.fetch(SECURITY_FEED, feed_records) if cves else asyncio.sleep(0, result=None),
                *(detail(url) for url in links[:8]),
            )
            records = list({row["source"]: row for row in [
                *(row for row in (feed or []) if set(cves).intersection(row["cves"])),
                *(row for row in details if row),
            ]}.values())
            records.sort(key=lambda row: RATINGS.index(row["severity"]))
            records = [{**row, "matched_cves": sorted(set(cves).intersection(row["cves"]))} for row in records]
        return {"cves": cves, "advisories": records, "linked": links, "field_notices": notices,
                "fix_source": fix["source"] if fix else None, "source": SECURITY_LOOKUP[family]}

    async def comparison(self, family, baseline, target):
        recommendations, old_security, security = await asyncio.gather(
            self.recommendations(family), self.security(family, baseline), self.security(family, target)
        )
        evidence = []
        for item in [*target["items"], *target["shared"]]:
            if item["category"] == "upgrade" and INSTALL_SIGNAL.search(item["text"]):
                if all(previous["text"] != item["text"] for previous in evidence):
                    evidence.append(item)
                if len(evidence) == 8:
                    break
        return {"recommendations": recommendations, "security": {"from": old_security, "to": security},
                "install": INSTALL_GUIDES[family], "install_evidence": evidence}
