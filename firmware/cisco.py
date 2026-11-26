import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

ORIGIN = "https://www.cisco.com"
SUPPORT = ORIGIN + "/c/en/us/support/"
FAMILIES = {
    "nexus": (
        "Nexus 9000 · NX-OS",
        SUPPORT + "switches/nexus-9000-series-switches/products-release-notes-list.html",
    ),
    "catalyst": (
        "Catalyst 9300 · IOS XE",
        SUPPORT + "switches/catalyst-9300-series-switches/products-release-notes-list.html",
    ),
    "ucs": (
        "UCS C-Series · Standalone",
        SUPPORT + "servers-unified-computing/ucs-c-series-integrated-management-controller/"
        "products-release-notes-list.tab2.html",
    ),
}
VERSION = {
    "nexus": re.compile(r"\b\d+\.\d+\(\d+[a-z]*\)[a-zA-Z]*(?!\w)"),
    "catalyst": re.compile(r"\b\d+\.\d+\.(?:\d+[a-z]?|x)\b"),
    "ucs": re.compile(r"\b\d+\.\d+\(\d+(?:\.\d+)?[a-z]?\)"),
}
TITLE = {
    "nexus": re.compile(r"^Cisco Nexus 9000 Series NX-OS Release Notes, Release ", re.I),
    "catalyst": re.compile(r"^Release Notes for Cisco Catalyst 9300 Series Switches,", re.I),
    "ucs": re.compile(r"^Release Notes for Cisco UCS (?:Rack Server|C-Series) Software,", re.I),
}
CATEGORIES = (
    ("history", r"(?:revision|change|document) history"),
    ("security", r"security (?:fix|advis|update)|vulnerabilit"),
    ("known", r"open (?:bug |severity [^ ]+ )?caveats|known (?:issue|behavio)|limitations|open issues"),
    ("fixed", r"resolved|fixed (?:issue|defect|bug)"),
    ("upgrade", r"upgrad|downgrad|release image|updating the firmware|rommon|important notes"),
    ("compatibility", r"compatib|supported (?:platform|hardware|cisco|network|optics)|device hardware"),
    ("features", r"feature|what.s new|new (?:software|hardware)|behavior changes"),
    ("overview", r"introduction|overview"),
)


@dataclass(frozen=True)
class Document:
    label: str
    url: str


def get_text(node):
    return " ".join(node.get_text(" ", strip=True).split())


def version_key(version):
    return tuple(int(part) if part.isdigit() else part.lower()
                 for part in re.findall(r"\d+|[A-Za-z]+", version))


def index_documents(family, html):
    soup = BeautifulSoup(html, "html.parser")
    documents = {}
    for anchor in soup.select("a[href]"):
        title = get_text(anchor)
        if not TITLE[family].match(title):
            continue
        match = VERSION[family].search(title)
        url = urljoin(FAMILIES[family][1], anchor["href"])
        parts = urlsplit(url)
        if match and parts.scheme == "https" and parts.netloc == "www.cisco.com" and parts.path.endswith(".html"):
            documents[url] = Document(match[0], url)
    if not documents:
        raise ValueError("Cisco 릴리스 목록에서 지원 문서를 찾지 못했습니다.")
    return list(documents.values())


def monitored_documents(family, documents, limit):
    if family != "nexus":
        return documents[:limit]
    # NX-OS 목록은 하나의 최신순 목록이 아니라 릴리스 계열별로 정렬된다.
    trains = {}
    for document in documents:
        train = document.label.split("(")[0]
        trains.setdefault(train, []).append(document)
    return [document for offset in range(2) for train in trains.values()
            for document in train[offset:offset + 1]][:limit]


def concrete_version(family, label, version):
    if family == "nexus":
        return version == label
    if family == "catalyst":
        return not version.endswith(".x") and (version == label or (label.endswith(".x") and version.startswith(label[:-1])))
    return re.fullmatch(re.escape(label[:-1]) + r"(?:\.\d+[a-z]?|[a-z])\)", version) is not None


def catalyst_chapters(document, html):
    soup = BeautifulSoup(html, "html.parser")
    prefix = document.url.removesuffix(".html") + "/"
    chapters = []
    for anchor in soup.select("#bookToc a[href]"):
        title = get_text(anchor)
        url = urljoin(document.url, anchor["href"])
        if url.startswith(prefix) and any(re.search(pattern, title, re.I) for _, pattern in CATEGORIES):
            chapters.append(Document(document.label, url))
        elif url.startswith(prefix) and title.lower() == "caveats":
            chapters.append(Document(document.label, url))
    return chapters


def parse_release_notes(family, document, html):
    soup = BeautifulSoup(html, "html.parser")
    body = soup.select_one("#chapterContent, main") or soup.select_one("#eot-doc-wrapper")
    if body is None:
        raise ValueError("릴리스 노트 본문을 찾지 못했습니다.")
    entries = {}
    shared = []
    headings = []
    for node in body.select("h1,h2,h3,h4,h5,h6,p,li,tr"):
        if node.find_parent(["nav", "aside", "footer"]):
            continue
        text = get_text(node)
        if not text:
            continue
        classes = node.get("class", [])
        word_heading = next((name for name in classes if re.fullmatch(r"pToC_Subhead[1-9]", name)), None)
        topic = next((name for name in classes if re.fullmatch(r"topictitle[1-9]", name)), None)
        if node.name.startswith("h") or word_heading:
            level = int((word_heading or topic or node.name)[-1])
            headings = [heading for heading in headings if heading[0] < level]
            category = next((name for name, pattern in CATEGORIES if re.search(pattern, text, re.I)), None)
            matches = VERSION[family].findall(text)
            version = next((v for v in matches if concrete_version(family, document.label, v)), None)
            if version and category:
                entries.setdefault(version, [])
            anchor = node.get("id") or (node.find("a", attrs={"name": True}) or {}).get("name")
            parent_article = node.find_parent("article", id=True)
            headings.append((level, category, version, anchor or (parent_article and parent_article["id"])))
            continue
        if node.find_parent(["tr", "li"]) or (node.name == "tr" and not node.find("td")):
            continue
        category = next((h[1] for h in reversed(headings) if h[1]), None)
        if not category:
            continue
        version = next((h[2] for h in reversed(headings) if h[2]), None)
        anchor = next((h[3] for h in reversed(headings) if h[3]), None)
        if category == "history" and family != "nexus":
            published = re.search(r"became available|initial release|created release notes for|release of", text, re.I)
            if published:
                versions = VERSION[family].findall(text)
                version = next((v for v in versions if concrete_version(family, document.label, v)), None)
        if category == "history" and not version:
            continue
        item = {"category": category, "text": text, "source": document.url + (f"#{anchor}" if anchor else "")}
        references = [
            urljoin(document.url, link["href"]) for link in node.select("a[href]")
            if "cisco-sa-" in link["href"] or "/field-notices/" in link["href"]
        ]
        if references:
            item["references"] = references
        if version:
            entries.setdefault(version, []).append(item)
        else:
            shared.append(item)

    if family == "nexus":
        entries.setdefault(document.label, []).extend(shared)
        shared = []
    if not (shared or any(entries.values())):
        raise ValueError("릴리스 노트에서 버전과 변경 항목을 추출하지 못했습니다.")
    return {"url": document.url, "label": document.label, "versions": entries, "shared": shared}
