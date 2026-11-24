"""去重过滤领域服务：通用资源骨架 + 指纹命中证据与调查采样编排。

状态流转仍只在 service 层发生，路由层只做参数解析与结果包装。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from app.core.dedup_sample import (
    DedupSamplePipeline, HitEvidence, DedupGroup, Investigation, SampleDelivery,
    SourceLocator, evidence_store, make_dedup_sample_pipeline,
)
from app.services.base import BaseModuleService


class DedupFilterService(BaseModuleService):
    MODULE = "dedup_filter"
    ENTITY = "去重规则"
    OPERATION_TERM = "去重"
    LIST_FIELDS = ["规则编号", "事件类型", "去重字段", "去重窗口", "指纹算法", "命中次数", "忽略次数", "规则状态"]
    REQUIRED_FIELDS = ["规则编号", "事件类型", "去重字段"]
    STATUS_ORDER = ["草稿", "生效中", "规则失效", "已停用"]
    ACTION_RULES = {"启效规则": "生效中", "标记失效": "规则失效", "停用规则": "已停用"}
    NEGATIVE_ACTIONS = ["停用规则"]

    def __init__(self) -> None:
        # 共享模块级证据仓库：查询端重启后调查与交付依据仍可恢复。
        self.pipeline: DedupSamplePipeline = make_dedup_sample_pipeline(evidence_store)

    # ---------- 序列化 ----------

    @staticmethod
    def _serialize_source(source: SourceLocator) -> dict[str, Any]:
        return {
            "source_id": source.source_id,
            "source_name": source.source_name,
            "app_label": source.app_label,
            "log_path": source.log_path,
            "line_number": source.line_number,
            "source_host": source.source_host,
        }

    def _serialize_hit(self, hit: HitEvidence) -> dict[str, Any]:
        group = self.pipeline.store.get_group(hit.group_id)
        return {
            "evidence_id": hit.evidence_id,
            "rule_id": hit.rule_id,
            "fingerprint": hit.fingerprint,
            "group_id": hit.group_id,
            "group_kind": group.kind if group else "unknown",
            "record_id": hit.record_id,
            "source": self._serialize_source(hit.source),
            "event_time": hit.event_time.isoformat(),
            "original_content": hit.original_content,
            "parsed_fields": dict(hit.parsed_fields),
            "is_representative": hit.is_representative,
            "retransmit_count": hit.retransmit_count,
            "replay_hit": hit.replay_hit,
        }

    def _serialize_group(self, group: DedupGroup) -> dict[str, Any]:
        members = self.pipeline.store.group_members(group)
        representative = self.pipeline.store.get_hit(group.representative_id) \
            if group.representative_id else None
        return {
            "group_id": group.group_id,
            "rule_id": group.rule_id,
            "fingerprint": group.fingerprint,
            "kind": group.kind,
            "is_disputed": group.is_disputed,
            "member_count": len(members),
            "evidence_ids": list(group.evidence_ids),
            "representative_id": group.representative_id,
            "representative_record_id": representative.record_id if representative else None,
            "anchor_time": group.anchor_time.isoformat() if group.anchor_time else None,
            "dispute_reasons": list(group.dispute_reasons),
            "sources": [self._serialize_source(hit.source) for hit in members],
        }

    def _serialize_investigation(self, inv: Investigation) -> dict[str, Any]:
        return {
            "investigation_id": inv.investigation_id,
            "rule_id": inv.rule_id,
            "investigator": inv.investigator,
            "plan_id": inv.plan_id,
            "status": inv.status,
            "claimed_group_ids": list(inv.claimed_group_ids),
            "claimed_snapshot": {gid: list(eids) for gid, eids in inv.claimed_snapshot.items()},
            "delivery_id": inv.delivery_id,
            "created_at": inv.created_at.isoformat(),
            "updated_at": inv.updated_at.isoformat(),
        }

    def _serialize_delivery(self, delivery: SampleDelivery) -> dict[str, Any]:
        return {
            "delivery_id": delivery.delivery_id,
            "investigation_id": delivery.investigation_id,
            "plan_id": delivery.plan_id,
            "representative_ids": list(delivery.representative_ids),
            "representatives": [
                self._serialize_hit(hit)
                for eid in delivery.representative_ids
                if (hit := self.pipeline.store.get_hit(eid)) is not None
            ],
            "group_ids": list(delivery.group_ids),
            "scope_sources": list(delivery.scope_sources),
            "scope_start": delivery.scope_start.isoformat() if delivery.scope_start else None,
            "scope_end": delivery.scope_end.isoformat() if delivery.scope_end else None,
            "refreshed": delivery.refreshed,
            "excluded_sources": list(delivery.excluded_sources),
            "created_at": delivery.created_at.isoformat(),
        }

    # ---------- 命中证据 / 重复组查询 ----------

    def list_hits(self, *, rule_id: str | None = None, fingerprint: str | None = None,
                  group_id: str | None = None, source: str | None = None,
                  start: datetime | None = None, end: datetime | None = None,
                  include_disputed: bool = True, page: int = 1,
                  size: int = 20) -> tuple[list[dict[str, Any]], int]:
        hits, total = self.pipeline.list_fingerprint_hits(
            rule_id=rule_id, fingerprint=fingerprint, group_id=group_id,
            source=source, start=start, end=end,
            include_disputed=include_disputed, page=page, size=size)
        return [self._serialize_hit(hit) for hit in hits], total

    def list_groups(self, *, rule_id: str | None = None,
                    kind: str | None = None) -> list[dict[str, Any]]:
        return [self._serialize_group(g) for g in self.pipeline.list_dedup_groups(
            rule_id=rule_id, kind=kind)]

    def get_group_detail(self, group_id: str) -> dict[str, Any] | None:
        group = self.pipeline.store.get_group(group_id)
        if group is None:
            return None
        payload = self._serialize_group(group)
        payload["members"] = [
            self._serialize_hit(hit) for hit in self.pipeline.store.group_members(group)
        ]
        return payload

    def locate_record(self, record_id: str, rule_id: str | None = None) -> dict[str, Any] | None:
        group = self.pipeline.locate_record_group(record_id, rule_id)
        if group is None:
            return None
        return self._serialize_group(group)

    # ---------- 调查 / 领用 / 采样 ----------

    def open_investigation(self, *, rule_id: str, investigator: str,
                           plan_id: str,
                           investigation_id: str | None = None) -> dict[str, Any]:
        inv = self.pipeline.open_investigation(
            rule_id=rule_id, investigator=investigator,
            plan_id=plan_id, investigation_id=investigation_id)
        return self._serialize_investigation(inv)

    def get_investigation(self, investigation_id: str) -> dict[str, Any] | None:
        inv = self.pipeline.store.get_investigation(investigation_id)
        return self._serialize_investigation(inv) if inv else None

    def claim_group(self, investigation_id: str, group_id: str) -> dict[str, Any]:
        inv, group, _ = self.pipeline.claim_duplicate_group(investigation_id, group_id)
        return {
            "investigation": self._serialize_investigation(inv),
            "group": self._serialize_group(group),
        }

    def run_sampling(self, *, investigation_id: str, plan_id: str | None = None,
                     scope_sources: list[str] | None = None,
                     scope_start: datetime | None = None,
                     scope_end: datetime | None = None,
                     refresh_scope: bool = False) -> dict[str, Any]:
        delivery = self.pipeline.run_investigation_sampling(
            investigation_id=investigation_id, plan_id=plan_id,
            scope_sources=scope_sources, scope_start=scope_start,
            scope_end=scope_end, refresh_scope=refresh_scope)
        inv = self.pipeline.store.get_investigation(investigation_id)
        return {
            "delivery": self._serialize_delivery(delivery),
            "investigation": self._serialize_investigation(inv) if inv else None,
        }

    def mark_source_error(self, source_id: str) -> None:
        self.pipeline.store.mark_source_error(source_id)

    def domain_snapshot(self) -> dict[str, Any]:
        """在通用快照上追加命中证据与争议组统计。"""
        snapshot = super().domain_snapshot()
        groups = self.pipeline.store.list_groups()
        snapshot.update({
            "hit_evidence": len(self.pipeline.store._hits),
            "duplicate_groups": sum(1 for g in groups if not g.is_disputed),
            "disputed_groups": sum(1 for g in groups if g.is_disputed),
        })
        return snapshot
