"""拾音工坊去重与采样归并管道：event_type→dedup_filter→sample_job。

数据流：事件分类 → 去重过滤 → 采样归并
涉及模块：event_type, dedup_filter, sample_job

本模块在原有“指纹命中计数”的基础上补齐调查链路：

- ``deduplicate`` 不再只返回计数，而是为每次命中保留**可定位的命中证据**
  （HitEvidence：指纹、原行编号、来源、路径、行号、时间），并把同指纹原行
  归并成可查询的重复组（DedupGroup）。
- 同指纹但矛盾字段取值冲突、或原始请求内容互相矛盾的原行进入**争议组**，
  任一原行都不会被折叠丢弃；调查采样只能从经核验的真实重复组取代表。
- 调查（Investigation）先领用重复组并冻结命中快照，再执行采样；采样代表来自
  领用快照或补齐后的有效输入，已交付样本不可被迟到数据覆盖。
"""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

from app.core.models import DedupFilter, EventRecord, SampleConfig


# ---------- 预置去重过滤规则 ----------

PRESET_DEDUP_RULES: list[DedupFilter] = [
    DedupFilter(
        rule_id="DEDU-0001",
        event_type_id="EVEN-0001",
        dedup_fields=["client_ip", "url"],
        window_minutes=60,
        fingerprint_algo="sha256",
        # 同一请求码（client_ip+url 指纹相同）但状态码/请求路径矛盾时，转入争议组。
        contradiction_fields=["status", "url", "method"],
    ),
    DedupFilter(
        rule_id="DEDU-0002",
        event_type_id="EVEN-0002",
        dedup_fields=["level", "message"],
        window_minutes=10,
        fingerprint_algo="sha256",
    ),
]

# ---------- 预置采样归并配置 ----------

PRESET_SAMPLE_CONFIGS: list[SampleConfig] = [
    SampleConfig(
        plan_id="SAMP-0001",
        event_type_id="EVEN-0001",
        sample_ratio=0.5,
        merge_key="client_ip",
        merge_window_minutes=5,
        retain_policy="latest",
    ),
    SampleConfig(
        plan_id="SAMP-0002",
        event_type_id="EVEN-0002",
        sample_ratio=1.0,
        merge_key="message",
        merge_window_minutes=10,
        retain_policy="latest",
    ),
]

# 组类型：经核验的真实重复 / 同指纹但内容矛盾的争议
GROUP_KIND_DUPLICATE = "duplicate"
GROUP_KIND_DISPUTED = "disputed"


# ---------- 可定位的命中证据与重复组 ----------

@dataclass
class SourceLocator:
    """原日志行的来源定位信息：能顺着它回到被折叠的那一行。"""
    source_id: str
    source_name: str = ""
    app_label: str = ""
    log_path: str = ""
    line_number: int = 0
    source_host: str = ""

    def matches(self, keyword: str) -> bool:
        needle = keyword.casefold()
        return any(
            needle in str(value).casefold()
            for value in (self.source_id, self.source_name, self.app_label,
                          self.log_path, self.source_host)
        )


@dataclass
class HitEvidence:
    """一条指纹命中证据：保留被折叠原行的完整定位与原始内容。"""
    evidence_id: str
    rule_id: str
    fingerprint: str
    group_id: str
    record_id: str
    source: SourceLocator
    event_time: datetime
    original_content: str
    parsed_fields: dict[str, str]
    is_representative: bool = False          # 是否为该组当前最新代表
    retransmit_count: int = 0                # 原行重传次数（重传只记一次命中）
    replay_hit: bool = False                 # 是否来自事件重放
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class DedupGroup:
    """同指纹原行的归并组：真实重复组或可定位的争议组。"""
    group_id: str
    rule_id: str
    fingerprint: str
    kind: str = GROUP_KIND_DUPLICATE
    evidence_ids: list[str] = field(default_factory=list)
    representative_id: str | None = None
    anchor_time: datetime | None = None      # 窗口锚点（首条原行时间）
    dispute_reasons: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)

    @property
    def is_disputed(self) -> bool:
        return self.kind == GROUP_KIND_DISPUTED


@dataclass
class SampleDelivery:
    """一次调查采样的交付依据：一经提交即冻结，迟到数据不能覆盖。"""
    delivery_id: str
    investigation_id: str
    plan_id: str
    representative_ids: list[str]
    group_ids: list[str]
    scope_sources: list[str]
    scope_start: datetime | None
    scope_end: datetime | None
    refreshed: bool
    excluded_sources: list[str]
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class Investigation:
    """一次去重调查：领用重复组、冻结快照、产出代表样本。"""
    investigation_id: str
    rule_id: str
    investigator: str
    plan_id: str
    status: str = "opened"                   # opened / claimed / submitted
    claimed_group_ids: list[str] = field(default_factory=list)
    # 领用时冻结的组快照：group_id -> 当时的 evidence_id 列表
    claimed_snapshot: dict[str, list[str]] = field(default_factory=dict)
    delivery_id: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class EvidenceStore:
    """线程安全的命中证据仓库：去重入口与采样入口共享同一份证据。

    模块级单例 ``evidence_store`` 被 API 层共享，因此查询端重启后
    （进程内重建管道但仓库对象保留）调查、领用与交付依据仍然可恢复。
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._groups: dict[str, DedupGroup] = {}
        # (rule_id, fingerprint) -> 按时间顺序产生的组列表（窗口切换会开新组）
        self._fp_index: dict[tuple[str, str], list[str]] = {}
        self._hits: dict[str, HitEvidence] = {}
        # (rule_id, record_id) -> evidence_id，原行重传只记一次命中
        self._record_index: dict[tuple[str, str], str] = {}
        self._investigations: dict[str, Investigation] = {}
        self._deliveries: dict[str, SampleDelivery] = {}
        # 被标记为错误来源的 source_id，采样候选必须排除
        self._error_sources: set[str] = set()
        self._seq = 0
        self._inv_seq = 0
        self._delivery_seq = 0

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def reset(self) -> None:
        """清空全部证据（测试隔离用，不影响业务表数据）。"""
        with self._lock:
            self._groups.clear()
            self._fp_index.clear()
            self._hits.clear()
            self._record_index.clear()
            self._investigations.clear()
            self._deliveries.clear()
            self._error_sources.clear()
            self._seq = 0
            self._inv_seq = 0
            self._delivery_seq = 0

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{self._seq:06d}"

    # ---------- 命中证据与组 ----------

    def find_group_in_window(self, rule_id: str, fingerprint: str,
                             event_time: datetime, window_minutes: int) -> DedupGroup | None:
        """找同指纹且仍在去重窗口内的最新组；窗口外返回 None（开新组）。"""
        for group_id in reversed(self._fp_index.get((rule_id, fingerprint), [])):
            group = self._groups[group_id]
            if group.anchor_time is not None and window_minutes > 0:
                if abs((event_time - group.anchor_time).total_seconds()) > window_minutes * 60:
                    continue
            return group
        return None

    def create_group(self, rule_id: str, fingerprint: str,
                     anchor_time: datetime) -> DedupGroup:
        group = DedupGroup(
            group_id=self._next_id("GRP"),
            rule_id=rule_id,
            fingerprint=fingerprint,
            anchor_time=anchor_time,
        )
        self._groups[group.group_id] = group
        self._fp_index.setdefault((rule_id, fingerprint), []).append(group.group_id)
        return group

    def record_hit(self, *, rule_id: str, fingerprint: str, group: DedupGroup,
                   record: EventRecord, source: SourceLocator,
                   is_representative: bool, replay: bool) -> HitEvidence:
        key = (rule_id, record.record_id)
        existing_id = self._record_index.get(key)
        if existing_id is not None:
            # 原行重传：命中证据只记一次，仅累加重传计数。
            existing = self._hits[existing_id]
            existing.retransmit_count += 1
            return existing
        evidence = HitEvidence(
            evidence_id=self._next_id("HIT"),
            rule_id=rule_id,
            fingerprint=fingerprint,
            group_id=group.group_id,
            record_id=record.record_id,
            source=source,
            event_time=record.event_time,
            original_content=record.original_content,
            parsed_fields=dict(record.parsed_fields),
            is_representative=is_representative,
            replay_hit=replay,
        )
        self._hits[evidence.evidence_id] = evidence
        self._record_index[key] = evidence.evidence_id
        group.evidence_ids.append(evidence.evidence_id)
        if is_representative:
            group.representative_id = evidence.evidence_id
        return evidence

    def mark_retransmit(self, evidence_id: str) -> None:
        if evidence_id in self._hits:
            self._hits[evidence_id].retransmit_count += 1

    def mark_disputed(self, group: DedupGroup, reasons: list[str]) -> None:
        group.kind = GROUP_KIND_DISPUTED
        for reason in reasons:
            if reason not in group.dispute_reasons:
                group.dispute_reasons.append(reason)

    def refresh_representative(self, group: DedupGroup) -> HitEvidence | None:
        """按最新 event_time 重新选出组代表（迟到原行可能刷新代表）。"""
        members = [self._hits[eid] for eid in group.evidence_ids]
        if not members:
            return None
        latest = max(members, key=lambda hit: (hit.event_time, hit.evidence_id))
        for hit in members:
            hit.is_representative = hit.evidence_id == latest.evidence_id
        group.representative_id = latest.evidence_id
        return latest

    def get_hit(self, evidence_id: str) -> HitEvidence | None:
        return self._hits.get(evidence_id)

    def get_group(self, group_id: str) -> DedupGroup | None:
        return self._groups.get(group_id)

    def group_members(self, group: DedupGroup) -> list[HitEvidence]:
        return [self._hits[eid] for eid in group.evidence_ids if eid in self._hits]

    def find_group_by_record(self, record_id: str, rule_id: str | None = None) -> DedupGroup | None:
        """按原行记录编号反查它所属的重复组/争议组。"""
        for (rid, rec_id), evidence_id in self._record_index.items():
            if rec_id != record_id:
                continue
            if rule_id is not None and rid != rule_id:
                continue
            hit = self._hits[evidence_id]
            return self._groups.get(hit.group_id)
        return None

    def list_hits(self, *, rule_id: str | None = None, fingerprint: str | None = None,
                  group_id: str | None = None, source: str | None = None,
                  start: datetime | None = None, end: datetime | None = None,
                  include_disputed: bool = True, page: int = 1,
                  size: int = 20) -> tuple[list[HitEvidence], int]:
        """可翻页的指纹命中明细：支持来源关键字与时间范围过滤。"""
        hits = list(self._hits.values())
        if rule_id is not None:
            hits = [h for h in hits if h.rule_id == rule_id]
        if fingerprint is not None:
            hits = [h for h in hits if h.fingerprint == fingerprint]
        if group_id is not None:
            hits = [h for h in hits if h.group_id == group_id]
        if not include_disputed:
            hits = [h for h in hits if not self._groups[h.group_id].is_disputed]
        if source:
            hits = [h for h in hits if h.source.matches(source)]
        if start is not None:
            hits = [h for h in hits if h.event_time >= start]
        if end is not None:
            hits = [h for h in hits if h.event_time <= end]
        hits.sort(key=lambda h: (h.event_time, h.evidence_id))
        total = len(hits)
        begin = (max(page, 1) - 1) * size
        return hits[begin:begin + size], total

    def list_groups(self, *, rule_id: str | None = None,
                    kind: str | None = None) -> list[DedupGroup]:
        groups = list(self._groups.values())
        if rule_id is not None:
            groups = [g for g in groups if g.rule_id == rule_id]
        if kind is not None:
            groups = [g for g in groups if g.kind == kind]
        return sorted(groups, key=lambda g: (g.anchor_time or datetime.min, g.group_id))

    # ---------- 错误来源 ----------

    def mark_source_error(self, source_id: str) -> None:
        self._error_sources.add(source_id)

    def clear_source_error(self, source_id: str) -> None:
        self._error_sources.discard(source_id)

    def is_error_source(self, source_id: str) -> bool:
        return source_id in self._error_sources

    # ---------- 调查 / 领用 / 交付 ----------

    def create_investigation(self, *, rule_id: str, investigator: str,
                             plan_id: str, investigation_id: str | None = None) -> Investigation:
        if investigation_id and investigation_id in self._investigations:
            return self._investigations[investigation_id]
        self._inv_seq += 1
        inv = Investigation(
            investigation_id=investigation_id or f"INV-{self._inv_seq:06d}",
            rule_id=rule_id,
            investigator=investigator,
            plan_id=plan_id,
        )
        self._investigations[inv.investigation_id] = inv
        return inv

    def get_investigation(self, investigation_id: str) -> Investigation | None:
        return self._investigations.get(investigation_id)

    def claim_group(self, investigation: Investigation, group: DedupGroup) -> tuple[bool, list[str]]:
        """领用一个经核验的重复组，冻结当时的命中快照。

        返回 (是否本次新领用, 冻结的 evidence_id 列表)。重复领用幂等，
        不会因为查询端重启、明细状态滞后而重复发出样本。
        """
        if group.is_disputed:
            raise ValueError("争议组未经核验，不能作为重复组领用")
        snapshot = list(group.evidence_ids)
        if group.group_id in investigation.claimed_group_ids:
            return False, list(investigation.claimed_snapshot.get(group.group_id, []))
        investigation.claimed_group_ids.append(group.group_id)
        investigation.claimed_snapshot[group.group_id] = snapshot
        investigation.status = "claimed"
        investigation.updated_at = datetime.now()
        return True, snapshot

    def save_delivery(self, delivery: SampleDelivery,
                      investigation: Investigation) -> SampleDelivery:
        existing = self._deliveries.get(delivery.delivery_id)
        if existing is not None:
            return existing
        # 同一调查已有交付：保留既有交付依据，拒绝覆盖。
        if investigation.delivery_id and investigation.delivery_id in self._deliveries:
            return self._deliveries[investigation.delivery_id]
        self._delivery_seq += 1
        self._deliveries[delivery.delivery_id] = delivery
        investigation.delivery_id = delivery.delivery_id
        investigation.status = "submitted"
        investigation.updated_at = datetime.now()
        return delivery

    def get_delivery(self, delivery_id: str) -> SampleDelivery | None:
        return self._deliveries.get(delivery_id)

    def next_delivery_id(self) -> str:
        self._delivery_seq += 1
        return f"DLV-{self._delivery_seq:06d}"


# 模块级共享证据仓库：API 路由与管道共用，支撑查询端重启后的调查恢复。
evidence_store = EvidenceStore()


class DedupSamplePipeline:
    """去重与采样归并处理管道。

    接收 EventRecord 集合 → dedup_filter 去重（留存可定位命中证据）
    → sample_job 采样归并（调查采样只取经核验重复组的最新代表）。
    """

    def __init__(self, dedup_rules: list[DedupFilter] | None = None,
                 sample_configs: list[SampleConfig] | None = None,
                 store: EvidenceStore | None = None):
        if dedup_rules is None:
            dedup_rules = PRESET_DEDUP_RULES
        if sample_configs is None:
            sample_configs = PRESET_SAMPLE_CONFIGS
        self.dedup_rules = dedup_rules
        self.sample_configs = sample_configs
        self.store = store if store is not None else EvidenceStore()
        self._fingerprint_store: dict[str, set[str]] = {}

    # ---------- 数据流 4: event_type → dedup_filter → sample_job ----------

    def deduplicate(self, records: list[EventRecord],
                    dedup_rule: DedupFilter, *,
                    source_resolver: Callable[[EventRecord], SourceLocator] | None = None,
                    replay: bool = False) -> tuple[list[EventRecord], int, int]:
        """对事件集合按 dedup_rule 执行去重。

        对每条事件按去重字段生成 SHA256 指纹，在去重窗口内判断重复，并为每次
        命中保留可定位证据（来源、路径、行号、时间、原始内容）。

        - 真实重复：仅组内首行通过，后续原行计入命中/忽略并挂到同一重复组；
        - 同指纹但矛盾字段（或原始请求内容）冲突：转入争议组，所有原行都保留；
        - 原行重传（同一 record_id）：只记一次命中，不累加成员、不重复计数。

        返回：(去重后记录列表, 命中次数, 忽略次数)
        """
        if self._fingerprint_store is None:
            self._fingerprint_store = {}
        key = dedup_rule.rule_id
        if key not in self._fingerprint_store:
            self._fingerprint_store[key] = set()

        seen = self._fingerprint_store[key]
        deduped: list[EventRecord] = []
        hit = 0

        for record in records:
            fp = dedup_rule.fingerprint(record)
            source = self._resolve_source(record, source_resolver)
            with self.store.lock:
                # 原行重传：同一原行只记一次命中。
                existing_evidence_id = self.store._record_index.get(
                    (dedup_rule.rule_id, record.record_id))
                if existing_evidence_id is not None:
                    self.store.mark_retransmit(existing_evidence_id)
                    dedup_rule.hit_count += 1
                    hit += 1
                    # 重传的原行不再次进入去重结果，也不新增忽略。
                    continue

                group = self.store.find_group_in_window(
                    dedup_rule.rule_id, fp, record.event_time,
                    dedup_rule.window_minutes)

                if fp not in seen or group is None:
                    # 窗口外的同指纹视为新一轮，不与旧组折叠。
                    if group is None:
                        group = self.store.create_group(
                            dedup_rule.rule_id, fp, record.event_time)
                    seen.add(fp)
                    self.store.record_hit(
                        rule_id=dedup_rule.rule_id, fingerprint=fp, group=group,
                        record=record, source=source,
                        is_representative=True, replay=replay)
                    deduped.append(record)
                    continue

                # 同指纹且在窗口内：判断是真实重复还是矛盾争议。
                reasons = self._contradiction_reasons(dedup_rule, group, record)
                if reasons:
                    self.store.mark_disputed(group, reasons)
                    self.store.record_hit(
                        rule_id=dedup_rule.rule_id, fingerprint=fp, group=group,
                        record=record, source=source,
                        is_representative=False, replay=replay)
                    self.store.refresh_representative(group)
                    # 争议原行不能因同指纹被丢掉，全部保留通过。
                    deduped.append(record)
                    continue

                # 真实重复：折叠并留存可定位命中证据。
                dedup_rule.hit_count += 1
                hit += 1
                dedup_rule.ignore_count += 1
                self.store.record_hit(
                    rule_id=dedup_rule.rule_id, fingerprint=fp, group=group,
                    record=record, source=source,
                    is_representative=False, replay=replay)
                self.store.refresh_representative(group)

        return deduped, hit, dedup_rule.ignore_count

    def replay_records(self, records: list[EventRecord], dedup_rule: DedupFilter, *,
                       source_resolver: Callable[[EventRecord], SourceLocator] | None = None
                       ) -> tuple[list[EventRecord], int, int]:
        """事件重放入口：重放产生的命中证据带 replay 标记，可与普通命中区分。"""
        return self.deduplicate(records, dedup_rule,
                                source_resolver=source_resolver, replay=True)

    def _contradiction_reasons(self, rule: DedupFilter, group: DedupGroup,
                               record: EventRecord) -> list[str]:
        """判断同指纹新原行与组内既有原行是否矛盾。"""
        rep = self.store.get_hit(group.representative_id) if group.representative_id else None
        if rep is None:
            return []
        reasons: list[str] = []
        for fname in rule.contradiction_fields:
            new_val = str(record.parsed_fields.get(fname, ""))
            old_val = str(rep.parsed_fields.get(fname, ""))
            if new_val != old_val:
                reasons.append(f"字段 {fname} 取值矛盾：{old_val!r} != {new_val!r}")
        # 原始请求内容互相矛盾（指纹字段之外的原始行不一致）也进入争议组。
        if record.original_content and rep.original_content \
                and record.original_content != rep.original_content and not reasons:
            # 仅当没有配置矛盾字段、但原始内容确实不同且解析字段无差异时提示。
            field_same = all(
                str(record.parsed_fields.get(f, "")) == str(rep.parsed_fields.get(f, ""))
                for f in rule.dedup_fields
            )
            if field_same and not rule.contradiction_fields:
                reasons.append("原始请求内容矛盾：指纹字段相同但原始日志行不一致")
        return reasons

    @staticmethod
    def _resolve_source(record: EventRecord,
                        resolver: Callable[[EventRecord], SourceLocator] | None) -> SourceLocator:
        if resolver is not None:
            return resolver(record)
        return SourceLocator(
            source_id=record.source_host or record.record_id,
            source_name=record.enriched_fields.get("app_name", "") if record.enriched_fields else "",
            app_label=record.enriched_fields.get("app_name", "") if record.enriched_fields else "",
            log_path=record.store_partition,
            source_host=record.source_host,
        )

    def deduplicate_all(self, records: list[EventRecord], *,
                        source_resolver: Callable[[EventRecord], SourceLocator] | None = None
                        ) -> list[EventRecord]:
        """按事件类型匹配去重规则批量去重。"""
        result: list[EventRecord] = list(records)
        for dedup_rule in self.dedup_rules:
            target_type_id = dedup_rule.event_type_id
            target_records = [r for r in result if r.event_type.type_id == target_type_id]
            other_records = [r for r in result if r.event_type.type_id != target_type_id]
            deduped, _, _ = self.deduplicate(
                target_records, dedup_rule, source_resolver=source_resolver)
            result = deduped + other_records
        return result

    # ---------- 采样归并 ----------

    def sample(self, records: list[EventRecord],
               config: SampleConfig) -> list[EventRecord]:
        """按采样配置进行采样归并。

        采样：按 sample_ratio 取前 N 条。
        归并：按 merge_key 分组，每组仅保留最新事件记录。
        """
        # 采样
        threshold = max(1, int(len(records) * config.sample_ratio))
        sampled = list(records[:threshold])

        # 归并
        if config.merge_key:
            merged: dict[str, EventRecord] = {}
            for record in sampled:
                mkey = record.parsed_fields.get(config.merge_key, "")
                if not mkey:
                    continue
                existing = merged.get(mkey)
                if existing is None or record.event_time > existing.event_time:
                    merged[mkey] = record
            return list(merged.values())
        return sampled

    def sample_all(self, records: list[EventRecord]) -> list[EventRecord]:
        """按事件类型匹配采样配置批量采样归并。"""
        result: list[EventRecord] = []
        handled_type_ids: set[str] = set()
        for config in self.sample_configs:
            target_type_id = config.event_type_id
            target_records = [r for r in records if r.event_type.type_id == target_type_id]
            handled_type_ids.add(target_type_id)
            sampled = self.sample(target_records, config)
            result.extend(sampled)
        # 未匹配采样配置的事件保留原样
        for record in records:
            if record.event_type.type_id not in handled_type_ids:
                result.append(record)
        return result

    # ---------- 调查：领用 → 快照/补齐 → 最新代表采样 ----------

    def open_investigation(self, *, rule_id: str, investigator: str,
                           plan_id: str,
                           investigation_id: str | None = None) -> Investigation:
        """开启或恢复一次调查；传入已存在的 investigation_id 即恢复原调查。"""
        with self.store.lock:
            return self.store.create_investigation(
                rule_id=rule_id, investigator=investigator,
                plan_id=plan_id, investigation_id=investigation_id)

    def claim_duplicate_group(self, investigation_id: str,
                              group_id: str) -> tuple[Investigation, DedupGroup, bool]:
        """调查员领用一个经核验的重复组，并发确认只保留本次调查的一份领用。

        返回 (调查, 重复组, 是否本次新领用)；重复领用幂等返回 False。
        """
        with self.store.lock:
            inv = self.store.get_investigation(investigation_id)
            if inv is None:
                raise KeyError(f"调查 {investigation_id} 不存在")
            group = self.store.get_group(group_id)
            if group is None:
                raise KeyError(f"重复组 {group_id} 不存在")
            newly_claimed, _ = self.store.claim_group(inv, group)
            return inv, group, newly_claimed

    def run_investigation_sampling(self, *, investigation_id: str,
                                   plan_id: str | None = None,
                                   scope_sources: list[str] | None = None,
                                   scope_start: datetime | None = None,
                                   scope_end: datetime | None = None,
                                   refresh_scope: bool = False
                                   ) -> SampleDelivery:
        """调查采样：以领用时冻结的命中快照、或补齐后的完整范围取最新代表。

        - 只能从经核验的真实重复组取代表，争议组不参与；
        - 来源/时间范围外、错误来源的原行不作为候选；
        - ``refresh_scope=False`` 用旧命中范围（领用时快照），迟到原行不影响；
        - ``refresh_scope=True`` 刷新到补全后的完整范围，可取时间更新的新代表；
        - 同一调查重复执行返回既有交付，迟到 P3 不能覆盖已交付的 P2。
        """
        with self.store.lock:
            inv = self.store.get_investigation(investigation_id)
            if inv is None:
                raise KeyError(f"调查 {investigation_id} 不存在")
            if inv.delivery_id:
                existing = self.store.get_delivery(inv.delivery_id)
                if existing is not None:
                    return existing

            config = self._find_sample_config(plan_id or inv.plan_id)
            scope_sources = scope_sources or []
            excluded_sources = sorted(
                sid for sid in self.store._error_sources
                if not scope_sources or sid in scope_sources
            )

            representative_ids: list[str] = []
            used_group_ids: list[str] = []
            for group_id in inv.claimed_group_ids:
                group = self.store.get_group(group_id)
                if group is None or group.is_disputed:
                    # 组在领用后被核验为争议：未经核验不能取代表。
                    continue
                if refresh_scope:
                    member_ids = list(group.evidence_ids)
                else:
                    # 严格使用领用快照：之后迟到的原行不在旧范围内。
                    member_ids = list(inv.claimed_snapshot.get(group_id, []))
                candidates = [
                    self.store.get_hit(eid) for eid in member_ids
                ]
                candidates = [c for c in candidates if c is not None]
                candidates = [
                    c for c in candidates
                    if self._in_scope(c, scope_sources, scope_start, scope_end)
                    and not self.store.is_error_source(c.source.source_id)
                ]
                if not candidates:
                    continue
                latest = max(candidates, key=lambda hit: (hit.event_time, hit.evidence_id))
                representative_ids.append(latest.evidence_id)
                used_group_ids.append(group_id)

            # 采样比例在“每组一个最新代表”的池上确定性生效，保留可复现的顺序。
            if representative_ids and config.sample_ratio < 1.0:
                threshold = max(1, int(len(representative_ids) * config.sample_ratio))
                representative_ids = representative_ids[:threshold]

            delivery = SampleDelivery(
                delivery_id=self.store.next_delivery_id(),
                investigation_id=investigation_id,
                plan_id=config.plan_id,
                representative_ids=representative_ids,
                group_ids=used_group_ids,
                scope_sources=list(scope_sources),
                scope_start=scope_start,
                scope_end=scope_end,
                refreshed=refresh_scope,
                excluded_sources=excluded_sources,
            )
            return self.store.save_delivery(delivery, inv)

    def _find_sample_config(self, plan_id: str) -> SampleConfig:
        for config in self.sample_configs:
            if config.plan_id == plan_id:
                return config
        raise KeyError(f"采样计划 {plan_id} 不存在")

    @staticmethod
    def _in_scope(hit: HitEvidence, scope_sources: list[str],
                  scope_start: datetime | None, scope_end: datetime | None) -> bool:
        if scope_sources and not any(
            hit.source.matches(sid) or sid.casefold() in hit.source.source_id.casefold()
            for sid in scope_sources
        ):
            return False
        if scope_start is not None and hit.event_time < scope_start:
            return False
        if scope_end is not None and hit.event_time > scope_end:
            return False
        return True

    # ---------- 查询入口 ----------

    def list_fingerprint_hits(self, *, rule_id: str | None = None,
                              fingerprint: str | None = None,
                              group_id: str | None = None,
                              source: str | None = None,
                              start: datetime | None = None,
                              end: datetime | None = None,
                              include_disputed: bool = True,
                              page: int = 1, size: int = 20
                              ) -> tuple[list[HitEvidence], int]:
        """可翻页的指纹命中明细查询。"""
        with self.store.lock:
            return self.store.list_hits(
                rule_id=rule_id, fingerprint=fingerprint, group_id=group_id,
                source=source, start=start, end=end,
                include_disputed=include_disputed, page=page, size=size)

    def list_dedup_groups(self, *, rule_id: str | None = None,
                          kind: str | None = None) -> list[DedupGroup]:
        with self.store.lock:
            return self.store.list_groups(rule_id=rule_id, kind=kind)

    def locate_record_group(self, record_id: str,
                            rule_id: str | None = None) -> DedupGroup | None:
        """从一条原行反查它所属的重复组及来源位置。"""
        with self.store.lock:
            return self.store.find_group_by_record(record_id, rule_id)

    def get_stats(self) -> dict[str, dict[str, int]]:
        """获取去重规则统计数据。"""
        stats: dict[str, dict[str, int]] = {}
        for rule in self.dedup_rules:
            stats[rule.rule_id] = {
                "hit_count": rule.hit_count,
                "ignore_count": rule.ignore_count,
            }
        return stats

    def reset_fingerprints(self):
        """重置指纹缓存与本管道命中证据（窗口周期结束或测试隔离用）。"""
        self._fingerprint_store.clear()
        self.store.reset()


def make_dedup_sample_pipeline(store: EvidenceStore | None = None) -> DedupSamplePipeline:
    """工厂函数：创建预配置的去重采样管道实例，默认挂到共享证据仓库。"""
    return DedupSamplePipeline(store=store or evidence_store)
