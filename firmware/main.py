import asyncio
import os
from contextlib import asynccontextmanager, suppress
from html import escape
from pathlib import Path
from typing import Literal

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from firmware.cisco import FAMILIES, VERSION
from firmware.guidance import CiscoGuidance
from firmware.monitor import Monitor, Store, compare, release_versions, releases
from firmware.summary import DEFAULT_MODEL, Summarizer

Family = Literal["nexus", "catalyst", "ucs"]
CATEGORY_LABELS = {
    "history": "릴리스 이력", "security": "보안", "known": "알려진 문제",
    "fixed": "수정된 문제", "upgrade": "업그레이드", "compatibility": "호환성",
    "features": "기능", "overview": "개요",
}
EVENT_LABELS = {"new_release": "새 릴리스", "document_revision": "문서 개정"}


def create_app(database_url=None, poll_seconds=3600, transport=None, groq_key=None, groq_model=DEFAULT_MODEL):
    @asynccontextmanager
    async def lifespan(app):
        store = Store(database_url)
        async with httpx.AsyncClient(
            timeout=15, follow_redirects=True, transport=transport, headers={"User-Agent": "FirmwareMonitor/0.1"}
        ) as client:
            monitor = Monitor(store, client)
            app.state.monitor = monitor
            app.state.guidance = CiscoGuidance(client)
            app.state.summarizer = Summarizer(client, groq_key, groq_model)
            task = asyncio.create_task(monitor.poll(poll_seconds)) if poll_seconds > 0 else None
            try:
                yield
            finally:
                if task:
                    task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task
                if store.engine is not None:
                    store.engine.dispose()

    app = FastAPI(title="Cisco 펌웨어 모니터", lifespan=lifespan)

    @app.get("/api/families")
    def families():
        return [{"id": key, "name": value[0], "source": value[1]} for key, value in FAMILIES.items()]

    @app.get("/api/{family}/releases")
    def versions(request: Request, family: Family):
        snapshot = request.app.state.monitor.store.get(family)
        return {
            "versions": release_versions(snapshot),
            "checked_at": snapshot.get("checked_at"),
            "errors": snapshot["errors"],
        }

    @app.get("/api/{family}/events")
    def events(request: Request, family: Family):
        return request.app.state.monitor.store.get(family)["events"]

    async def comparison(request, family, before, after):
        if not all(VERSION[family].fullmatch(version) for version in (before, after)):
            raise HTTPException(422, "이 장비군에 맞는 두 버전 번호를 입력하세요.")
        try:
            snapshot = await request.app.state.monitor.load_missing(family, (before, after))
            result = compare(snapshot, before, after)
            versions = releases(snapshot)
            result["guidance"] = await request.app.state.guidance.comparison(family, versions[before], versions[after])
            return result
        except KeyError as exc:
            raise HTTPException(404, f"Cisco 문서에서 버전을 찾지 못했습니다. {exc.args[0]}") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise HTTPException(502, f"Cisco 문서를 읽지 못했습니다. {exc}") from exc

    @app.get("/api/{family}/compare")
    async def compare_api(
        request: Request, family: Family, before: str = Query(max_length=40), after: str = Query(max_length=40),
        summarize: bool = False,
    ):
        result = await comparison(request, family, before, after)
        if summarize:
            result["summary"] = await request.app.state.summarizer.summarize(FAMILIES[family][0], result)
        return result

    @app.post("/api/{family}/scan")
    async def scan_api(request: Request, family: Family):
        monitor = request.app.state.monitor
        await monitor.scan(family)
        return versions(request, family)

    @app.post("/scan/{family}", include_in_schema=False)
    async def scan_ui(request: Request, family: Family):
        await request.app.state.monitor.scan(family)
        return RedirectResponse(f"/?family={family}", status_code=303)

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def home(
        request: Request, family: Family = "nexus", before: str = Query("", max_length=40),
        after: str = Query("", max_length=40),
    ):
        monitor = request.app.state.monitor
        result = None
        error = ""
        if before and after:
            try:
                result = await comparison(request, family, before.strip(), after.strip())
                result['summary'] = await request.app.state.summarizer.summarize(FAMILIES[family][0], result)
            except HTTPException as exc:
                error = str(exc.detail)
        recommendations = (result["guidance"]["recommendations"] if result
                           else await request.app.state.guidance.recommendations(family))
        return render(family, monitor.store.get(family), before, after, result, error, recommendations)

    return app


def link(url, label="Cisco 원문"):
    return f'<a href="{escape(url, quote=True)}">{escape(label)}</a>'


def item_list(items):
    visible = items[:20]
    rows = "".join(
        f'<li><strong>{CATEGORY_LABELS[item["category"]]}</strong> {escape(item["text"][:500])} '
        f'{link(item["source"], "원문")}</li>'
        for item in visible
    )
    rest = f"<p>외 {len(items) - len(visible)}개 · 전체 항목은 API에서 확인</p>" if len(items) > len(visible) else ""
    return f"<ul>{rows}</ul>{rest}" if rows else "<p>감지된 항목 없음</p>"


def render_summary(summary):
    if summary["status"] != "ok":
        message = {
            "no_changes": "수집된 문서에서 텍스트 차이를 찾지 못했습니다.",
            "baseline_only": "차이는 기준 문서에서만 확인됩니다. 아래에서 해당 항목을 볼 수 있습니다.",
            "not_configured": "Groq 키가 설정되면 이곳에 AI 요약이 표시됩니다.",
            "unavailable": "지금은 AI 요약을 가져오지 못했습니다. 아래에서 문서 차이를 확인할 수 있습니다.",
        }[summary["status"]]
        return f"<p>{message}</p>"
    points = []
    for point in summary["points"]:
        sources = " · ".join(link(url, f"근거 {index}") for index, url in enumerate(point["sources"], 1))
        points.append(
            f'<li><small>{escape(point["kind"])}</small> <strong>{escape(point["title"])}</strong>'
            f'<div>{escape(point["detail"])} <small>{sources}</small></div></li>'
        )
    return f'<div class="brief"><p><strong>AI 요약</strong> {escape(summary["overview"])}</p><ul>{"".join(points)}</ul></div>'


def render_recommendations(data, before="", after=""):
    source = link(data["source"])
    if data["rows"] is None:
        status = "이 장비군의 권장판은 모델별 Cisco 문서에서 확인하세요." if not data["available"] else "Cisco 권장판 표를 불러오지 못했습니다."
        return f"<p>{status} {source}</p>"
    matches = []
    for version, label in ((after, "목표"), (before, "기준")):
        if any(version in row["versions"] for row in data["rows"]):
            matches.append(f'<span class="guidance-tag">{label} {escape(version)} · Cisco 권장</span>')
    rows = "".join(
        f'<li><strong>{escape(", ".join(row["versions"]))}</strong> · {escape(row["condition"])}</li>'
        for row in data["rows"]
    )
    message = "".join(matches) or ("<span>선택한 버전은 조회한 권장 표에 없습니다.</span>" if after else "")
    return (f'{message}<details><summary>Cisco 권장 버전과 적용 조건</summary>'
            f'<ul>{rows}</ul>{source}</details>')


def render_security(data, label, version):
    entries = []
    for row in data["advisories"]:
        severity = row["severity"]
        tone = " danger" if severity in {"Critical", "High"} else ""
        cvss = f' · 공지 CVSS {escape(row["cvss"])}' if row["cvss"] else ""
        cves = ", ".join(row["matched_cves"] or row["cves"])
        entries.append(
            f'<li><strong class="guidance-tag{tone}">Cisco {escape(severity)}{cvss}</strong> '
            f'{link(row["source"], row["title"])} <small>{escape(cves)}</small></li>'
        )
    if not entries:
        entries.append("<li>릴리스 노트와 연결된 Cisco 공지에서 심각도를 확인하지 못했습니다.</li>")
    references = [link(url, "연결된 보안 공지") for url in data["linked"] if url not in {row["source"] for row in data["advisories"]}]
    references += [link(url, "Cisco Field Notice") for url in data["field_notices"]]
    fix = f'<p><strong>보안 수정 언급</strong> · {link(data["fix_source"], "릴리스 노트")}</p>' if data["fix_source"] else ""
    cves = f'<p><small>릴리스 노트 CVE · {escape(", ".join(data["cves"]))}</small></p>' if data["cves"] else ""
    return (f'<div class="security-version"><strong>{label} {escape(version)}</strong>{fix}{cves}'
            f'<ul>{"".join(entries)}</ul><small>{" · ".join(references)}</small></div>')


def render_guidance(result):
    data = result["guidance"]
    security = "".join(
        render_security(data["security"][side], label, result[side])
        for side, label in (("to", "목표"), ("from", "기준")) if side == "to" or result["from"] != result["to"]
    )
    methods = "".join(
        f'<li><strong>{escape(label)}</strong> · {escape(text)} {link(source)}</li>'
        for label, text, source in data["install"]
    )
    evidence = (
        f'<details><summary>목표 릴리스 노트의 재부팅·설치 관련 문구</summary>{item_list(data["install_evidence"])}</details>'
        if data["install_evidence"] else "<p><small>수집한 목표 릴리스 노트에서 버전별 재부팅·설치 조건을 확인하지 못했습니다.</small></p>"
    )
    return f"""
    <div class="guidance"><h3>업데이트 전 확인</h3>
    {render_recommendations(data['recommendations'], result['from'], result['to'])}
    <h4>Cisco 보안 공지 심각도</h4>{security}
    <p><small>수집한 릴리스 노트에 연결된 공지의 심각도입니다. 전체 공지와 장비 적용 여부, 수정 버전은 Cisco에서 확인하세요. {link(data['security']['to']['source'], 'Cisco 보안 조회')}</small></p>
    <h4>재부팅·설치 방식</h4><ul>{methods}</ul>{evidence}</div>"""


def render_diff(result):
    columns = (
        ("removed", "−", "기준", result["from"]),
        ("added", "+", "목표", result["to"]),
    )
    by_category = {}
    for side, _, _, _ in columns:
        for item in result[side]:
            by_category.setdefault(item["category"], {}).setdefault(side, []).append(item)

    headers = "".join(
        f'<div><strong>{label} {escape(version)}</strong><small>{symbol}{len(result[side])}</small></div>'
        for side, symbol, label, version in columns
    )
    sections = []
    for category, label in CATEGORY_LABELS.items():
        if category not in by_category:
            continue
        panes = []
        for side, symbol, side_label, _ in columns:
            lines = []
            for item in by_category[category].get(side, ()):
                version = item.get("document_version")
                context = f'<small class="diff-version">중간 버전 {escape(version)}</small>' if version else ""
                lines.append(
                    f'<li class="diff-{side}"><span class="diff-sign" aria-hidden="true">{symbol}</span>'
                    f'<div>{context}{escape(item["text"])} <small>{link(item["source"], "원문")}</small></div></li>'
                )
            rows = "".join(lines) or '<li class="diff-empty">변경 항목 없음</li>'
            panes.append(f'<ul aria-label="{side_label} · {label}">{rows}</ul>')
        sections.append(f'<h4 class="diff-category">{label}</h4><div class="diff-grid">{"".join(panes)}</div>')

    content = (
        f'<div class="diff-view"><div class="diff-grid diff-head">{headers}</div>{"".join(sections)}</div>'
        if sections else "<p>감지된 문서 차이 없음</p>"
    )
    sources = " · ".join(link(url, f"문서 {index}") for index, url in enumerate(result["sources"], 1))
    middle = ", ".join(result["intermediate"]) or "없음"
    return f"""
    <details class="diff"><summary>문서 차이 <span>−{len(result['removed'])} · +{len(result['added'])}</span></summary>
    <p><small>− 기준 쪽에서만 확인 · + 목표 쪽에서 확인. 문서의 표기 차이입니다.</small></p>
    {content}
    <p><small>수집된 중간 버전 {escape(middle)} · {sources}</small></p></details>"""


def render(family, snapshot, before, after, result, error, recommendations):
    tabs = " · ".join(
        f'<strong>{escape(name)}</strong>' if key == family else link(f"/?family={key}", name)
        for key, (name, _) in FAMILIES.items()
    )
    versions = release_versions(snapshot)
    options = "".join(f'<option value="{escape(version, quote=True)}">' for version in versions)
    status = escape(snapshot.get("checked_at", "첫 수집 대기 중"))
    problems = "".join(f"<li>{escape(message)}</li>" for message in snapshot["errors"])
    problem_list = f"<details><summary>수집 오류 {len(snapshot['errors'])}건</summary><ul>{problems}</ul></details>" if problems else ""
    recommended_versions = {version for row in recommendations["rows"] or [] for version in row["versions"]}
    event_cards = ""
    for event in snapshot["events"][:10]:
        rec = event["recommendation"]
        evidence = item_list([rec["evidence"]]) if rec["evidence"] else ""
        recommended = ' <span class="guidance-tag">Cisco 권장</span>' if event["version"] in recommended_versions else ""
        event_cards += f"""
        <details><summary>{EVENT_LABELS[event['kind']]} · {escape(event['version'])} · 예비 등급 {rec['grade']}{recommended}</summary>
        <p>{rec['action']} · {link(event['source'])}</p>{evidence}
        <h3>추가</h3>{item_list(event['added'])}<h3>삭제</h3>{item_list(event['removed'])}</details>"""
    comparison_html = f'<p role="alert">{escape(error)}</p>' if error else ""
    if result:
        comparison_html = f"""
        <h3>{escape(result['from'])} → {escape(result['to'])}</h3>
        {render_guidance(result)}
        {render_summary(result['summary'])}
        <p><small>{escape(result['coverage'])}</small></p>
        {render_diff(result)}"""
    general_guidance = render_recommendations(recommendations) if not result else ""
    return f"""<!doctype html>
<html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cisco 펌웨어 모니터</title>
<style>
body{{font:16px/1.6 system-ui,sans-serif;max-width:55rem;margin:2rem auto;padding:0 1rem;color:#1a2633}}
a{{color:#07569c}} h1,h2,h3{{line-height:1.25}} section{{border-top:1px solid #ccd4dd;margin-top:1.5rem}}
label,input,button{{margin:0 .3rem .4rem 0}} input,button{{font:inherit;padding:.25rem .45rem}}
.brief{{background:#f2f6fa;border-left:3px solid #07569c;padding:.25rem 1rem}}
.brief li{{margin:.6rem 0}}
.guidance{{background:#f5f7fa;border:1px solid #cad4dd;padding:.6rem 1rem;margin-bottom:1rem;border-radius:.45rem}}
.guidance h3,.guidance h4{{margin:.55rem 0}}
.guidance ul{{margin:.35rem 0;padding-left:1.35rem}}
.guidance p{{margin:.4rem 0}}
.security-version{{margin-top:.5rem}}
.guidance-tag{{display:inline-block;background:#e3efff;color:#174472;border-radius:.3rem;padding:.05rem .45rem;margin-right:.35rem;font-weight:650}}
.guidance-tag.danger{{background:#ffe3de;color:#861c14}}
details{{margin:.6rem 0}} summary{{cursor:pointer}} li{{overflow-wrap:anywhere}} small{{color:#415368}}
.diff{{border:1px solid #cad4dd;border-radius:.45rem}}
.diff summary{{padding:.65rem .85rem;font-weight:650}}
.diff summary span{{margin-left:.6rem;color:#415368;font-variant-numeric:tabular-nums}}
.diff>p{{margin:.6rem .85rem}}
.diff-view{{overflow-x:auto}}
.diff-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));min-width:32rem}}
.diff-head{{background:#eef2f6}}
.diff-head>div{{display:flex;justify-content:space-between;gap:.5rem;padding:.55rem .75rem}}
.diff-grid>*+*{{border-left:1px solid #cad4dd}}
.diff-grid ul{{padding:0;margin:0;list-style:none}}
.diff-category{{font-size:.85rem;margin:0;padding:.3rem .75rem;border-block:1px solid #cad4dd;background:#f6f8fa}}
.diff-grid li{{display:grid;grid-template-columns:1rem minmax(0,1fr);gap:.4rem;padding:.4rem .65rem;border-bottom:1px solid #cad4dd66}}
.diff-sign{{font:700 1rem/1.6 ui-monospace,monospace}}
.diff-removed{{background:#ffebe9;color:#70211f}}
.diff-added{{background:#e6ffec;color:#114527}}
.diff-grid .diff-empty{{display:block;background:#fafbfc;color:#536275}}
.diff-version{{display:block}}
</style>
<h1>Cisco 펌웨어 모니터</h1><nav>{tabs}</nav>
<p><small>최근 확인 {status} · 수집 버전 {len(versions)}개</small></p>
<form method="post" action="/scan/{family}"><button>지금 확인</button> {link(FAMILIES[family][1], "Cisco 릴리스 목록")}</form>
{problem_list}
{general_guidance}
<section><h2>버전 비교</h2><form>
<input type="hidden" name="family" value="{family}">
<label>기준 <input name="before" list="versions" maxlength="40" value="{escape(before, quote=True)}" required></label>
<label>목표 <input name="after" list="versions" maxlength="40" value="{escape(after, quote=True)}" required></label>
<datalist id="versions">{options}</datalist><button>비교</button></form>{comparison_html}</section>
<section><h2>감지된 변경</h2>{event_cards or '<p>첫 수집을 기준으로 이후 릴리스와 문서 변경이 표시됩니다.</p>'}</section>
<p><a href="/docs">API 문서</a></p></html>"""


load_dotenv(Path(__file__).resolve().parent.parent / ".env")
app = create_app(
    os.getenv("FIRMWARE_DATABASE_URL"), float(os.getenv("FIRMWARE_POLL_SECONDS", "3600")),
    groq_key=os.getenv("GROQ_API_KEY") or os.getenv("groq_api_key"),
    groq_model=os.getenv("GROQ_MODEL") or DEFAULT_MODEL,
)
