"""去重调查路由：分页指纹命中明细、重复组/争议组查询、调查领用与采样。

路由层只做参数解析和结果包装，业务判断全部在 DedupFilterService。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.schemas import PageResult
from app.services.dedup_filter import DedupFilterService

router = APIRouter(prefix="/api/dedup", tags=["去重调查"])
service = DedupFilterService()


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"时间格式无法解析：{value}")


class InvestigationPayload(BaseModel):
    rule_id: str
    investigator: str = "调查员"
    plan_id: str
    investigation_id: str | None = None


class ClaimPayload(BaseModel):
    group_id: str


class SamplingPayload(BaseModel):
    plan_id: str | None = None
    scope_sources: list[str] = Field(default_factory=list)
    scope_start: str | None = None
    scope_end: str | None = None
    refresh_scope: bool = False


@router.get("/hits", response_model=PageResult[dict])
def list_hits(
    rule_id: str | None = Query(default=None),
    fingerprint: str | None = Query(default=None),
    group_id: str | None = Query(default=None),
    source: str | None = Query(default=None),
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    include_disputed: bool = Query(default=True),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=200),
) -> PageResult[dict]:
    """可翻页的指纹命中明细：按来源与时间范围查询被折叠的原日志。"""
    items, total = service.list_hits(
        rule_id=rule_id, fingerprint=fingerprint, group_id=group_id,
        source=source, start=_parse_time(start), end=_parse_time(end),
        include_disputed=include_disputed, page=page, size=size)
    return PageResult(items=items, total=total, page=page, size=size)


@router.get("/groups")
def list_groups(rule_id: str | None = Query(default=None),
                kind: str | None = Query(default=None)) -> dict[str, Any]:
    return {"items": service.list_groups(rule_id=rule_id, kind=kind)}


@router.get("/groups/{group_id}")
def group_detail(group_id: str) -> dict[str, Any]:
    detail = service.get_group_detail(group_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"重复组 {group_id} 不存在")
    return detail


@router.get("/records/{record_id}/group")
def locate_record(record_id: str,
                  rule_id: str | None = Query(default=None)) -> dict[str, Any]:
    group = service.locate_record(record_id, rule_id)
    if group is None:
        raise HTTPException(status_code=404, detail=f"原行 {record_id} 没有对应的去重组")
    return group


@router.post("/investigations")
def open_investigation(payload: InvestigationPayload) -> dict[str, Any]:
    return service.open_investigation(
        rule_id=payload.rule_id, investigator=payload.investigator,
        plan_id=payload.plan_id, investigation_id=payload.investigation_id)


@router.get("/investigations/{investigation_id}")
def get_investigation(investigation_id: str) -> dict[str, Any]:
    inv = service.get_investigation(investigation_id)
    if inv is None:
        raise HTTPException(status_code=404, detail=f"调查 {investigation_id} 不存在")
    return inv


@router.post("/investigations/{investigation_id}/claims")
def claim_group(investigation_id: str, payload: ClaimPayload) -> dict[str, Any]:
    try:
        return service.claim_group(investigation_id, payload.group_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/investigations/{investigation_id}/sampling")
def run_sampling(investigation_id: str, payload: SamplingPayload) -> dict[str, Any]:
    try:
        return service.run_sampling(
            investigation_id=investigation_id, plan_id=payload.plan_id,
            scope_sources=payload.scope_sources,
            scope_start=_parse_time(payload.scope_start),
            scope_end=_parse_time(payload.scope_end),
            refresh_scope=payload.refresh_scope)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/sources/{source_id}/error")
def mark_source_error(source_id: str) -> dict[str, Any]:
    service.mark_source_error(source_id)
    return {"ok": True, "message": f"来源 {source_id} 已标记为错误来源"}


@router.post("/demo-seed")
def load_demo_evidence() -> dict[str, Any]:
    """装载演示命中证据（幂等），供前端面板联调。"""
    from app.core.dedup_demo import seed_shared_evidence
    return {"ok": True, **seed_shared_evidence()}
