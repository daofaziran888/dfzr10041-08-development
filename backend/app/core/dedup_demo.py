"""去重调查演示数据：构造可定位命中、争议组、跨来源重复与迟到原行场景。

仅用于联调与手工验证；通过 API 显式装载，幂等（按 record_id 去重）。
"""
from __future__ import annotations

from datetime import datetime, timedelta

from app.core.dedup_sample import (
    DedupSamplePipeline, SourceLocator, evidence_store,
)
from app.core.models import DedupFilter, EventRecord, EventTypeDef

RULE = DedupFilter(
    rule_id="DEDU-DEMO",
    event_type_id="EVEN-0001",
    dedup_fields=["request_code"],
    window_minutes=60,
    contradiction_fields=["status", "url"],
)

BASE_TIME = datetime(2026, 11, 24, 10, 0, 0)


def _event(record_id: str, request_code: str, status: str, url: str,
           minute: int, original: str, host: str) -> EventRecord:
    return EventRecord(
        record_id=record_id,
        event_type=EventTypeDef(
            type_id="EVEN-0001", type_name="访问事件",
            category_tag="access", severity="INFO",
        ),
        original_content=original,
        parsed_fields={"request_code": request_code, "status": status, "url": url},
        masked_fields={},
        enriched_fields={"app_name": host},
        event_time=BASE_TIME + timedelta(minutes=minute),
        source_host=host,
        store_partition="20261124",
    )


def _resolver(record: EventRecord) -> SourceLocator:
    return SourceLocator(
        source_id=record.source_host,
        source_name=record.enriched_fields.get("app_name", ""),
        app_label=record.enriched_fields.get("app_name", ""),
        log_path=f"/var/log/{record.source_host}/access.log",
        line_number=int(record.record_id.split("-")[-1]),
        source_host=record.source_host,
    )


def build_demo_pipeline() -> DedupSamplePipeline:
    """构造一条装载了演示数据的管道（独立 EvidenceStore，便于测试）。"""
    from app.core.dedup_sample import EvidenceStore
    pipeline = DedupSamplePipeline(
        dedup_rules=[RULE], sample_configs=[], store=EvidenceStore())
    records = demo_records()
    pipeline.deduplicate(records, RULE, source_resolver=_resolver)
    return pipeline


def demo_records() -> list[EventRecord]:
    """P1 代表 + P2/Q2 跨来源重复 + 矛盾争议组 R1/R2 + 一条重传。"""
    return [
        # 真实重复组：请求码 REQ-1001，P1 为代表，P2（排查应用）与 Q2（其他来源）
        _event("REC-0001", "REQ-1001", "200", "/api/order", 0,
               'GET /api/order 200 (P1)', "app-under-review"),
        _event("REC-0002", "REQ-1001", "200", "/api/order", 2,
               'GET /api/order 200 (P2)', "app-under-review"),
        _event("REC-0003", "REQ-1001", "200", "/api/order", 3,
               'GET /api/order 200 (Q2)', "other-source"),
        # 争议组：同请求码 REQ-2002，但状态与请求路径互相矛盾
        _event("REC-0004", "REQ-2002", "200", "/api/pay", 5,
               'POST /api/pay 200 (R1)', "app-under-review"),
        _event("REC-0005", "REQ-2002", "500", "/api/refund", 6,
               'POST /api/refund 500 (R2)', "app-under-review"),
        # P2 原行重传：只记一次命中
        _event("REC-0002", "REQ-1001", "200", "/api/order", 9,
               'GET /api/order 200 (P2 retry)', "app-under-review"),
    ]


def seed_shared_evidence() -> dict[str, int]:
    """把演示数据装载到共享证据仓库（已存在的 record_id 会被幂等跳过）。"""
    pipeline = DedupSamplePipeline(
        dedup_rules=[RULE], sample_configs=[], store=evidence_store)
    before = len(evidence_store._hits)
    pipeline.deduplicate(demo_records(), RULE, source_resolver=_resolver)
    after = len(evidence_store._hits)
    groups = evidence_store.list_groups(rule_id="DEDU-DEMO")
    return {
        "new_hits": after - before,
        "total_hits": after,
        "groups": len(groups),
        "disputed_groups": sum(1 for g in groups if g.is_disputed),
    }
