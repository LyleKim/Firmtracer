import asyncio
import re
from datetime import datetime, timezone

import httpx
from sqlalchemy import JSON, Column, MetaData, String, Table, create_engine, select

from firmware.cisco import FAMILIES, catalyst_chapters, concrete_version, index_documents, monitored_documents, parse_release_notes, version_key

LEVELS = {
    "권장": "핵심 변경을 확인하고 정기 업데이트 후보로 검토",
    "필요": "적용 조건을 확인하고 변경 계획 수립",
    "필수": "적용 조건을 확인하고 우선 검토 및 변경 승인 절차 착수",
    "판정 보류": "Cisco 원문에서 변경 내용과 적용 조건을 확인",
}


def recommend(items):
    candidates = [item for item in items if item["category"] != "known"]
    mandatory = next((item for item in candidates if re.search(
        r"\b(?:mandatory (?:firmware |software )?(?:update|upgrade)|(?:must|required to) (?:immediately |promptly )(?:update|upgrade))\b",
        item["text"], re.I
    )), None)
    needed = next((item for item in candidates if item["category"] == "security" or re.search(
        r"\b(?:contains only security fixes|addresses (?:a |an )?critical|fixes (?:a |an )?critical)\b",
        item["text"], re.I
    )), None)
    evidence = mandatory or needed or (items[0] if items else None)
    grade = "필수" if mandatory else "필요" if needed else "권장" if evidence else "판정 보류"
    return {"grade": grade, "action": LEVELS[grade], "evidence": evidence}


def unique(items):
    return list({(item["category"], item["text"]): item for item in items}.values())


def difference(before, after):
    existing = {(item["category"], item["text"]) for item in before}
    return [item for item in unique(after) if (item["category"], item["text"]) not in existing]


class Store:
    def __init__(self, database_url=None):
        self.data = {}
        self.engine = create_engine(database_url) if database_url else None
        if self.engine is not None:
            metadata = MetaData()
            self.table = Table(
                "firmware_snapshots", metadata,
                Column("family", String(32), primary_key=True),
                Column("snapshot", JSON, nullable=False),
            )
            metadata.create_all(self.engine)
            with self.engine.connect() as connection:
                self.data = {family: snapshot for family, snapshot in connection.execute(select(self.table))}

    def get(self, family):
        return self.data.get(family, {"documents": {}, "events": [], "errors": []})

    def save(self, family, snapshot):
        if self.engine is not None:
            with self.engine.begin() as connection:
                result = connection.execute(
                    self.table.update().where(self.table.c.family == family).values(snapshot=snapshot)
                )
                if result.rowcount == 0:
                    connection.execute(self.table.insert().values(family=family, snapshot=snapshot))
        self.data[family] = snapshot


def releases(snapshot):
    return {
        version: {"version": version, "source": document["url"], "items": items, "shared": document["shared"]}
        for document in snapshot["documents"].values()
        for version, items in document["versions"].items()
    }


def release_versions(snapshot):
    return sorted(releases(snapshot), key=version_key, reverse=True)


def compare(snapshot, before, after):
    versions = releases(snapshot)
    start, target = versions[before], versions[after]
    low, high = sorted((version_key(before), version_key(after)))
    intermediate = sorted(
        (version for version in versions if low < version_key(version) < high), key=version_key
    )
    forward = version_key(before) < version_key(after)
    # Features and closed defects may be recorded only in the release that introduced them.
    cumulative = [
        {**item, "document_version": version}
        for version in intermediate for item in versions[version]["items"]
        if item["category"] in {"features", "fixed", "security"}
    ] if forward else []
    old = start["items"] + start["shared"]
    new = target["items"] + target["shared"]
    added = difference(old, new + difference(new, cumulative))
    return {
        "from": before, "to": after,
        "sources": list(dict.fromkeys([start["source"], *(versions[v]["source"] for v in intermediate), target["source"]])),
        "intermediate": intermediate,
        "coverage": "수집된 문서 기준입니다. 중간 버전 누락 또는 직접 업그레이드 가능 여부는 Cisco 원문에서 확인하세요.",
        "added": added,
        "removed": difference(new, old),
    }


def changes(previous, documents, timestamp):
    known = releases(previous)
    events = []
    for url, current in documents.items():
        old = previous["documents"].get(url)
        for version, items in current["versions"].items():
            if version not in known:
                events.append(event("new_release", version, current, items, [], timestamp))
            elif old and version in old["versions"]:
                added = difference(old["versions"][version], items)
                removed = difference(items, old["versions"][version])
                if added or removed:
                    events.append(event("document_revision", version, current, added, removed, timestamp))
        if old:
            added = difference(old["shared"], current["shared"])
            removed = difference(current["shared"], old["shared"])
            if added or removed:
                events.append(event("document_revision", current["label"], current, added, removed, timestamp))
    return events


def event(kind, version, document, added, removed, timestamp):
    # Shared guidance can describe several versions. Grade only release-specific evidence.
    return {
        "kind": kind, "version": version, "source": document["url"], "detected_at": timestamp,
        "recommendation": recommend(added), "added": added, "removed": removed,
    }


class Monitor:
    def __init__(self, store, client, limit=12):
        self.store = store
        self.client = client
        self.limit = limit
        self.lock = asyncio.Lock()
        self.requests = asyncio.Semaphore(4)

    async def fetch(self, url):
        async with self.requests:
            response = await self.client.get(url)
            response.raise_for_status()
            return response.text

    async def extract(self, family, document):
        html = await self.fetch(document.url)
        if family == "catalyst":
            chapters = await asyncio.to_thread(catalyst_chapters, document, html)
            if chapters:
                parsed = await asyncio.gather(*(self.extract_chapter(family, chapter) for chapter in chapters))
                versions = {}
                for chapter in parsed:
                    for version, items in chapter["versions"].items():
                        versions.setdefault(version, []).extend(items)
                if not versions:
                    raise ValueError("Cisco 문서에서 패치 버전을 찾지 못했습니다.")
                return {"url": document.url, "label": document.label, "versions": versions,
                        "shared": [item for chapter in parsed for item in chapter["shared"]]}
        result = await asyncio.to_thread(parse_release_notes, family, document, html)
        if not result["versions"]:
            raise ValueError("Cisco 문서에서 패치 버전을 찾지 못했습니다.")
        return result

    async def extract_chapter(self, family, chapter):
        html = await self.fetch(chapter.url)
        return await asyncio.to_thread(parse_release_notes, family, chapter, html)

    async def load_missing(self, family, requested):
        snapshot = self.store.get(family)
        missing = set(requested) - releases(snapshot).keys()
        if not missing:
            return snapshot
        catalog = index_documents(family, await self.fetch(FAMILIES[family][1]))
        matches = [
            document for document in catalog
            if any(concrete_version(family, document.label, version) for version in missing)
        ]
        loaded = await asyncio.gather(*(self.extract(family, doc) for doc in matches))
        return {**snapshot, "documents": snapshot["documents"] | {doc["url"]: doc for doc in loaded}}

    async def scan_family(self, family):
        previous = self.store.get(family)
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        errors = []
        observed = {}
        try:
            catalog = index_documents(family, await self.fetch(FAMILIES[family][1]))
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(str(exc))
        else:
            documents = monitored_documents(family, catalog, self.limit)
            results = await asyncio.gather(
                *(self.extract(family, document) for document in documents), return_exceptions=True
            )
            for document, result in zip(documents, results):
                if isinstance(result, Exception):
                    errors.append(f"{document.label} · {result}")
                else:
                    observed[document.url] = result

        events = changes(previous, observed, timestamp) if previous.get("checked_at") and previous["documents"] else []
        snapshot = {
            "documents": previous["documents"] | observed,
            "events": (events + previous["events"])[:100],
            "errors": errors,
            "checked_at": timestamp,
        }
        self.store.save(family, snapshot)

    async def scan(self, family=None):
        async with self.lock:
            await asyncio.gather(*(self.scan_family(key) for key in ([family] if family else FAMILIES)))

    async def poll(self, seconds):
        while True:
            await self.scan()
            await asyncio.sleep(seconds)
