"""测试：指纹命中证据、争议组与调查采样完整链路。

覆盖需求：
- 去重保留可定位命中证据，可按来源/时间范围翻页查询被折叠原日志
- 同指纹矛盾记录进入争议组，任一原行不被折叠
- 调查采样只从经核验重复组取最新代表，按领用快照或补齐范围取样
- 重启恢复、已交付不重发、迟到 P3 不覆盖 P2
- 来源/时间范围过滤、重传统计一次、并发确认只留一份样本
- 重放后矛盾两笔证据都可查；错误来源候选被排除
"""
from __future__ import annotations

import os
import sys
import threading
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.dedup_sample import (  # noqa: E402
    DedupSamplePipeline, EvidenceStore, GROUP_KIND_DISPUTED,
    GROUP_KIND_DUPLICATE, HitEvidence, SourceLocator,
)
from app.core.models import (  # noqa: E402
    DedupFilter, EventRecord, EventTypeDef, SampleConfig,
)

RULE = DedupFilter(
    rule_id="DEDU-T",
    event_type_id="EVEN-0001",
    dedup_fields=["request_code"],
    window_minutes=60,
    contradiction_fields=["status", "url"],
)


def fresh_rule() -> DedupFilter:
    """每个用例独立的规则实例，避免命中计数在不同用例间累计。"""
    import copy
    return copy.deepcopy(RULE)
SAMPLE_CONFIG = SampleConfig(
    plan_id="SAMP-T", event_type_id="EVEN-0001",
    sample_ratio=1.0, merge_key="",
)
BASE = datetime(2026, 11, 24, 10, 0, 0)
APP_A = "app-under-review"
APP_B = "other-source"


def make_event(record_id: str, code: str, *, status: str = "200",
               url: str = "/api/order", minute: int = 0,
               source: str = APP_A, original: str | None = None) -> EventRecord:
    return EventRecord(
        record_id=record_id,
        event_type=EventTypeDef(
            type_id="EVEN-0001", type_name="访问事件",
            category_tag="access", severity="INFO",
        ),
        original_content=original or f"{code} {status} {url} {record_id}",
        parsed_fields={"request_code": code, "status": status, "url": url},
        masked_fields={},
        enriched_fields={"app_name": source},
        event_time=BASE + timedelta(minutes=minute),
        source_host=source,
        store_partition="20261124",
    )


_LINE_COUNTER: dict[str, int] = {}


def resolver(record: EventRecord) -> SourceLocator:
    key = record.record_id
    line_number = _LINE_COUNTER.setdefault(key, len(_LINE_COUNTER) + 1)
    return SourceLocator(
        source_id=record.source_host,
        source_name=record.enriched_fields["app_name"],
        app_label=record.enriched_fields["app_name"],
        log_path=f"/var/log/{record.source_host}/access.log",
        line_number=line_number,
        source_host=record.source_host,
    )


def make_pipeline(store: EvidenceStore | None = None) -> DedupSamplePipeline:
    return DedupSamplePipeline(
        dedup_rules=[fresh_rule()], sample_configs=[SAMPLE_CONFIG],
        store=store or EvidenceStore())


def run(records: list[EventRecord], store: EvidenceStore | None = None
        ) -> tuple[DedupSamplePipeline, list[EventRecord], int, int]:
    pipeline = make_pipeline(store)
    deduped, hit, ignored = pipeline.deduplicate(
        records, fresh_rule(), source_resolver=resolver)
    return pipeline, deduped, hit, ignored


# ---------- 1. 可定位命中证据与翻页查询 ----------

class TestHitEvidence:

    def test_dedup_keeps_locatable_evidence(self):
        """去重折叠后仍能按来源和时间范围查到被折叠原行及其位置。"""
        records = [
            make_event("P1", "REQ-1", minute=0),
            make_event("P2", "REQ-1", minute=2),
            make_event("P3", "REQ-1", minute=4),
        ]
        pipeline, deduped, hit, ignored = run(records)
        assert len(deduped) == 1          # P2/P3 被折叠
        assert hit == 2 and ignored == 2

        hits, total = pipeline.list_fingerprint_hits(
            rule_id="DEDU-T", source=APP_A,
            start=BASE + timedelta(minutes=1),
            end=BASE + timedelta(minutes=3), page=1, size=10)
        assert total == 1
        p2 = hits[0]
        assert p2.record_id == "P2"
        assert p2.source.log_path == f"/var/log/{APP_A}/access.log"
        assert p2.source.line_number == 2
        assert p2.original_content.startswith("REQ-1")

    def test_hits_pagination(self):
        """命中明细可翻页，总数不受页码影响。"""
        records = [make_event("P1", "REQ-1", minute=0)]
        records += [make_event(f"D{i}", "REQ-1", minute=i + 1) for i in range(1, 6)]
        pipeline, _, _, _ = run(records)
        page1, total = pipeline.list_fingerprint_hits(
            rule_id="DEDU-T", page=1, size=2)
        page2, _ = pipeline.list_fingerprint_hits(
            rule_id="DEDU-T", page=2, size=2)
        page3, _ = pipeline.list_fingerprint_hits(
            rule_id="DEDU-T", page=3, size=2)
        assert total == 6
        assert [h.record_id for h in page1] == ["P1", "D1"]
        assert [h.record_id for h in page2] == ["D2", "D3"]
        assert [h.record_id for h in page3] == ["D4", "D5"]

    def test_locate_group_and_source_from_record(self):
        """能从一条原行查到所属重复组及来源位置。"""
        records = [
            make_event("P1", "REQ-1", minute=0),
            make_event("P2", "REQ-1", minute=2),
        ]
        pipeline, _, _, _ = run(records)
        group = pipeline.locate_record_group("P2", rule_id="DEDU-T")
        assert group is not None and not group.is_disputed
        members = pipeline.store.group_members(group)
        assert {m.record_id for m in members} == {"P1", "P2"}
        p2 = next(m for m in members if m.record_id == "P2")
        assert p2.source.source_id == APP_A
        assert group.representative_id is not None

    def test_time_range_outside_rows_are_not_candidates(self):
        """时间范围外的原行不能被查询到，也不会成为候选。"""
        records = [
            make_event("P1", "REQ-1", minute=0),
            make_event("P2", "REQ-1", minute=30),
            make_event("P3", "REQ-1", minute=120),
        ]
        pipeline, _, _, _ = run(records)
        hits, total = pipeline.list_fingerprint_hits(
            rule_id="DEDU-T",
            start=BASE + timedelta(minutes=10),
            end=BASE + timedelta(minutes=60))
        assert [h.record_id for h in hits] == ["P2"]
        assert total == 1

    def test_retransmit_recorded_once(self):
        """原行重传只记一次命中，不新增组成员。"""
        records = [
            make_event("P1", "REQ-1", minute=0),
            make_event("P2", "REQ-1", minute=2),
            make_event("P2", "REQ-1", minute=2, original="REQ-1 200 /api/order P2 retry"),
        ]
        pipeline, deduped, hit, _ = run(records)
        assert len(deduped) == 1
        assert hit == 2  # P2 两次出现只产生一次折叠命中 + 一次重传计数
        group = pipeline.store.list_groups(rule_id="DEDU-T")[0]
        assert len(group.evidence_ids) == 2
        p2_hit = next(h for h in pipeline.store.group_members(group)
                      if h.record_id == "P2")
        assert p2_hit.retransmit_count == 1


# ---------- 2. 真实重复 vs 争议组 ----------

class TestDisputedGroup:

    def test_contradicting_rows_go_to_disputed_group(self):
        """同请求码但状态和请求路径矛盾的原行进入争议组，均不被折叠。"""
        records = [
            make_event("R1", "REQ-9", status="200", url="/api/pay", minute=0),
            make_event("R2", "REQ-9", status="500", url="/api/refund", minute=1),
        ]
        pipeline, deduped, hit, ignored = run(records)
        # 争议行不折叠、不计命中也不计忽略，两笔原行全部保留
        assert hit == 0 and ignored == 0
        assert [r.record_id for r in deduped] == ["R1", "R2"]
        groups = pipeline.store.list_groups(rule_id="DEDU-T")
        assert len(groups) == 1
        group = groups[0]
        assert group.kind == GROUP_KIND_DISPUTED
        assert any("status" in reason for reason in group.dispute_reasons)
        members = pipeline.store.group_members(group)
        assert {m.record_id for m in members} == {"R1", "R2"}

    def test_replay_keeps_both_contradicting_evidence(self):
        """重放后两笔矛盾证据都能查到，不会作为普通重复折叠。"""
        records = [
            make_event("R1", "REQ-9", status="200", url="/api/pay", minute=0),
            make_event("R2", "REQ-9", status="500", url="/api/refund", minute=1),
        ]
        pipeline = make_pipeline()
        deduped, hit, _ = pipeline.replay_records(
            records, fresh_rule(), source_resolver=resolver)
        assert len(deduped) == 2 and hit == 0
        hits, total = pipeline.list_fingerprint_hits(rule_id="DEDU-T")
        assert total == 2
        assert all(h.replay_hit for h in hits)
        group = pipeline.store.list_groups(rule_id="DEDU-T")[0]
        assert group.is_disputed

    def test_sampling_rejects_disputed_group(self):
        """调查采样只能从经核验的重复组取代表，争议组领用直接被拒。"""
        records = [
            make_event("R1", "REQ-9", status="200", url="/api/pay", minute=0),
            make_event("R2", "REQ-9", status="500", url="/api/refund", minute=1),
        ]
        pipeline, _, _, _ = run(records)
        group = pipeline.store.list_groups(rule_id="DEDU-T")[0]
        inv = pipeline.open_investigation(
            rule_id="DEDU-T", investigator="tester", plan_id="SAMP-T")
        try:
            pipeline.claim_duplicate_group(inv.investigation_id, group.group_id)
        except ValueError:
            return
        raise AssertionError("争议组不应允许领用")

    def test_window_expiry_opens_new_group(self):
        """窗口外的同指纹不与旧组折叠，另开新组。"""
        records = [
            make_event("P1", "REQ-1", minute=0),
            make_event("P2", "REQ-1", minute=61),
        ]
        pipeline, deduped, hit, _ = run(records)
        assert len(deduped) == 2 and hit == 0
        groups = pipeline.store.list_groups(rule_id="DEDU-T")
        assert len(groups) == 2
        assert all(g.kind == GROUP_KIND_DUPLICATE for g in groups)


# ---------- 3. 调查采样：快照、补齐、代表归并 ----------

class TestInvestigationSampling:

    def _p1_p2_q2(self) -> tuple[DedupSamplePipeline, str]:
        records = [
            make_event("P1", "REQ-1", minute=0, source=APP_A),
            make_event("P2", "REQ-1", minute=2, source=APP_A),
            make_event("Q2", "REQ-1", minute=3, source=APP_B),
        ]
        pipeline, _, _, _ = run(records)
        return pipeline, pipeline.store.list_groups(rule_id="DEDU-T")[0].group_id

    def test_source_filter_only_returns_app_rows(self):
        """按排查应用查询只应看到该应用的 P1 和 P2，看不到其他来源 Q2。"""
        pipeline, group_id = self._p1_p2_q2()
        hits, total = pipeline.list_fingerprint_hits(
            rule_id="DEDU-T", source=APP_A)
        assert total == 2
        assert {h.record_id for h in hits} == {"P1", "P2"}
        hits_b, total_b = pipeline.list_fingerprint_hits(
            rule_id="DEDU-T", source=APP_B)
        assert total_b == 1 and hits_b[0].record_id == "Q2"

    def test_claim_snapshot_vs_refreshed_scope_with_late_p3(self):
        """旧命中范围可采 P2，刷新完整范围可采时间更新的迟到 P3。"""
        pipeline, group_id = self._p1_p2_q2()
        inv = pipeline.open_investigation(
            rule_id="DEDU-T", investigator="tester", plan_id="SAMP-T")
        pipeline.claim_duplicate_group(inv.investigation_id, group_id)

        # 领用之后、运行取样前，同指纹 P3 从排查应用迟到
        late = [make_event("P3", "REQ-1", minute=8, source=APP_A)]
        pipeline.deduplicate(late, fresh_rule(), source_resolver=resolver)

        # 旧范围（领用快照）：P3 不在快照内，代表仍是快照中的最新 P2
        delivery_old = pipeline.run_investigation_sampling(
            investigation_id=inv.investigation_id,
            scope_sources=[APP_A], refresh_scope=False)
        assert delivery_old.representative_ids
        old_rep = pipeline.store.get_hit(delivery_old.representative_ids[0])
        assert old_rep.record_id == "P2"

        # 新调查刷新完整范围：可采到时间更新的 P3
        inv2 = pipeline.open_investigation(
            rule_id="DEDU-T", investigator="tester", plan_id="SAMP-T")
        pipeline.claim_duplicate_group(inv2.investigation_id, group_id)
        delivery_new = pipeline.run_investigation_sampling(
            investigation_id=inv2.investigation_id,
            scope_sources=[APP_A], refresh_scope=True)
        new_rep = pipeline.store.get_hit(delivery_new.representative_ids[0])
        assert new_rep.record_id == "P3"

    def test_out_of_scope_sources_excluded_from_candidates(self):
        """不同来源和时间范围外的原行不能成为采样候选。"""
        pipeline, group_id = self._p1_p2_q2()
        inv = pipeline.open_investigation(
            rule_id="DEDU-T", investigator="tester", plan_id="SAMP-T")
        pipeline.claim_duplicate_group(inv.investigation_id, group_id)
        delivery = pipeline.run_investigation_sampling(
            investigation_id=inv.investigation_id,
            scope_sources=[APP_A],
            scope_start=BASE,
            scope_end=BASE + timedelta(minutes=2, seconds=30),
            refresh_scope=True)
        # Q2 来源不符；P1 时间最早也在范围内，P2 是范围内最新代表
        rep = pipeline.store.get_hit(delivery.representative_ids[0])
        assert rep.record_id == "P2"
        assert rep.source.source_id == APP_A

    def test_error_source_excluded(self):
        """错误来源的原行被排除出候选。"""
        records = [
            make_event("P1", "REQ-1", minute=0, source=APP_A),
            make_event("P2", "REQ-1", minute=2, source=APP_A),
        ]
        pipeline, _, _, _ = run(records)
        pipeline.store.mark_source_error(APP_A)
        group_id = pipeline.store.list_groups(rule_id="DEDU-T")[0].group_id
        inv = pipeline.open_investigation(
            rule_id="DEDU-T", investigator="tester", plan_id="SAMP-T")
        pipeline.claim_duplicate_group(inv.investigation_id, group_id)
        delivery = pipeline.run_investigation_sampling(
            investigation_id=inv.investigation_id,
            scope_sources=[APP_A], refresh_scope=True)
        assert delivery.representative_ids == []
        assert APP_A in delivery.excluded_sources

    def test_delivery_frozen_and_not_overwritten_by_late_p3(self):
        """P2 已交付后，迟到 P3 不能覆盖既有交付依据，也不会重发 P2。"""
        pipeline, group_id = self._p1_p2_q2()
        inv = pipeline.open_investigation(
            rule_id="DEDU-T", investigator="tester", plan_id="SAMP-T",
            investigation_id="INV-FIXED")
        pipeline.claim_duplicate_group(inv.investigation_id, group_id)
        first = pipeline.run_investigation_sampling(
            investigation_id=inv.investigation_id,
            scope_sources=[APP_A], refresh_scope=False)
        first_rep = pipeline.store.get_hit(first.representative_ids[0])
        assert first_rep.record_id == "P2"

        # P3 迟到
        pipeline.deduplicate(
            [make_event("P3", "REQ-1", minute=9, source=APP_A)],
            fresh_rule(), source_resolver=resolver)

        # 即使明细仍标未交付、即使要求刷新范围，恢复原调查再取样也返回原交付
        again = pipeline.run_investigation_sampling(
            investigation_id="INV-FIXED", scope_sources=[APP_A],
            refresh_scope=True)
        assert again.delivery_id == first.delivery_id
        rep = pipeline.store.get_hit(again.representative_ids[0])
        assert rep.record_id == "P2"
        recovered = pipeline.store.get_investigation("INV-FIXED")
        assert recovered.status == "submitted"
        assert recovered.delivery_id == first.delivery_id

    def test_restart_recovery_keeps_claim_and_delivery(self):
        """查询端重启（新管道共享同一证据仓库）后调查、领用、交付可恢复。"""
        shared = EvidenceStore()
        pipeline, _, _, _ = run([
            make_event("P1", "REQ-1", minute=0),
            make_event("P2", "REQ-1", minute=2),
        ], store=shared)
        group_id = shared.list_groups(rule_id="DEDU-T")[0].group_id
        inv = pipeline.open_investigation(
            rule_id="DEDU-T", investigator="tester", plan_id="SAMP-T",
            investigation_id="INV-RESTART")
        pipeline.claim_duplicate_group(inv.investigation_id, group_id)
        delivery = pipeline.run_investigation_sampling(
            investigation_id="INV-RESTART", refresh_scope=True)
        delivered_id = delivery.delivery_id

        # 模拟重启：全新管道实例挂回同一仓库
        restarted = make_pipeline(shared)
        recovered = restarted.store.get_investigation("INV-RESTART")
        assert recovered is not None
        assert group_id in recovered.claimed_group_ids
        assert recovered.claimed_snapshot[group_id]
        again = restarted.run_investigation_sampling(
            investigation_id="INV-RESTART", refresh_scope=True)
        # 不会因为明细状态滞后重发，也不会生成新交付
        assert again.delivery_id == delivered_id
        assert again.representative_ids == delivery.representative_ids

    def test_restart_then_late_p3_keeps_p2_delivery(self):
        """完整恢复场景：P2 已交付、明细未确认时查询端重启，P3 才到。

        恢复原调查领后续样本时：不能因明细仍标未交付再发 P2，
        也不能用 P3 覆盖 P2 的既有交付依据；新调查刷新范围才能采 P3。
        """
        shared = EvidenceStore()
        pipeline, _, _, _ = run([
            make_event("P1", "REQ-1", minute=0, source=APP_A),
            make_event("P2", "REQ-1", minute=2, source=APP_A),
        ], store=shared)
        group_id = shared.list_groups(rule_id="DEDU-T")[0].group_id
        inv = pipeline.open_investigation(
            rule_id="DEDU-T", investigator="tester", plan_id="SAMP-T",
            investigation_id="INV-RECOVER")
        pipeline.claim_duplicate_group(inv.investigation_id, group_id)
        first = pipeline.run_investigation_sampling(
            investigation_id="INV-RECOVER",
            scope_sources=[APP_A], refresh_scope=False)
        assert shared.get_hit(first.representative_ids[0]).record_id == "P2"

        # 查询端重启：全新管道挂回共享仓库，随后迟到 P3 才写入
        restarted = make_pipeline(shared)
        restarted.deduplicate(
            [make_event("P3", "REQ-1", minute=9, source=APP_A)],
            fresh_rule(), source_resolver=resolver)

        # 恢复原调查（明细可能仍标未交付）：直接返回既有交付，不重发、不覆盖
        again = restarted.run_investigation_sampling(
            investigation_id="INV-RECOVER",
            scope_sources=[APP_A], refresh_scope=True)
        assert again.delivery_id == first.delivery_id
        assert shared.get_hit(again.representative_ids[0]).record_id == "P2"

        # 新的调查刷新补全范围，才能采到时间更新的 P3
        inv2 = restarted.open_investigation(
            rule_id="DEDU-T", investigator="tester", plan_id="SAMP-T")
        restarted.claim_duplicate_group(inv2.investigation_id, group_id)
        fresh = restarted.run_investigation_sampling(
            investigation_id=inv2.investigation_id,
            scope_sources=[APP_A], refresh_scope=True)
        assert shared.get_hit(fresh.representative_ids[0]).record_id == "P3"

    def test_concurrent_claim_keeps_single_sample(self):
        """并发确认只保留这次调查的一份领用与一份样本。"""
        pipeline, group_id = self._p1_p2_q2()
        inv = pipeline.open_investigation(
            rule_id="DEDU-T", investigator="tester", plan_id="SAMP-T",
            investigation_id="INV-CONC")
        outcomes: list[bool] = []

        def claim() -> None:
            _, _, is_claimed = pipeline.claim_duplicate_group(
                "INV-CONC", group_id)
            outcomes.append(is_claimed)

        threads = [threading.Thread(target=claim) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sum(outcomes) == 1          # 仅首次为新领用
        assert inv.claimed_group_ids.count(group_id) == 1

        deliveries = []

        def sample() -> None:
            deliveries.append(pipeline.run_investigation_sampling(
                investigation_id="INV-CONC", refresh_scope=True).delivery_id)

        threads = [threading.Thread(target=sample) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(set(deliveries)) == 1   # 并发采样只落一份交付

    def test_evidence_priority_only_affects_unsubmitted_investigation(self):
        """证据优先级（刷新代表）只影响尚未提交的调查。"""
        pipeline, group_id = self._p1_p2_q2()
        inv_done = pipeline.open_investigation(
            rule_id="DEDU-T", investigator="tester", plan_id="SAMP-T",
            investigation_id="INV-DONE")
        pipeline.claim_duplicate_group(inv_done.investigation_id, group_id)
        frozen = pipeline.run_investigation_sampling(
            investigation_id="INV-DONE", refresh_scope=False)

        inv_open = pipeline.open_investigation(
            rule_id="DEDU-T", investigator="tester", plan_id="SAMP-T",
            investigation_id="INV-OPEN")
        pipeline.claim_duplicate_group(inv_open.investigation_id, group_id)

        # 新证据 P3 到达并刷新组代表
        pipeline.deduplicate(
            [make_event("P3", "REQ-1", minute=9, source=APP_A)],
            fresh_rule(), source_resolver=resolver)

        # 已提交调查的交付不变
        again = pipeline.run_investigation_sampling(
            investigation_id="INV-DONE", refresh_scope=True)
        assert again.delivery_id == frozen.delivery_id
        # 未提交调查刷新范围后采用新代表 P3
        fresh = pipeline.run_investigation_sampling(
            investigation_id="INV-OPEN", refresh_scope=True)
        rep = pipeline.store.get_hit(fresh.representative_ids[0])
        assert rep.record_id == "P3"


# ---------- 4. 端到端交错：确认与 P3 写入并发 ----------

class TestInterleavedFlow:

    def test_interleaved_confirm_and_late_write(self):
        """交错执行确认与 P3 写入，实际跑最新代表采样并核对结果。"""
        store = EvidenceStore()
        pipeline, _, _, _ = run([
            make_event("P1", "REQ-1", minute=0, source=APP_A),
            make_event("P2", "REQ-1", minute=2, source=APP_A),
            make_event("Q2", "REQ-1", minute=3, source=APP_B),
        ], store=store)
        group_id = store.list_groups(rule_id="DEDU-T")[0].group_id
        inv = pipeline.open_investigation(
            rule_id="DEDU-T", investigator="tester", plan_id="SAMP-T",
            investigation_id="INV-INTER")
        pipeline.claim_duplicate_group(inv.investigation_id, group_id)

        barrier = threading.Barrier(2)

        def write_p3() -> None:
            barrier.wait()
            pipeline.deduplicate(
                [make_event("P3", "REQ-1", minute=9, source=APP_A)],
                fresh_rule(), source_resolver=resolver)

        def confirm() -> None:
            barrier.wait()
            pipeline.run_investigation_sampling(
                investigation_id="INV-INTER",
                scope_sources=[APP_A], refresh_scope=False)

        t1 = threading.Thread(target=write_p3)
        t2 = threading.Thread(target=confirm)
        t1.start(); t2.start()
        t1.join(); t2.join()

        submitted = store.get_investigation("INV-INTER")
        assert submitted.delivery_id is not None
        delivery = store.get_delivery(submitted.delivery_id)
        # 快照模式：无论 P3 何时写入，交付代表只能来自领用快照
        rep = store.get_hit(delivery.representative_ids[0])
        assert rep.record_id in {"P1", "P2"}
        assert rep.record_id != "P3"
        # 刷新完整范围的新调查可取 P3
        inv2 = pipeline.open_investigation(
            rule_id="DEDU-T", investigator="tester", plan_id="SAMP-T")
        pipeline.claim_duplicate_group(inv2.investigation_id, group_id)
        refreshed = pipeline.run_investigation_sampling(
            investigation_id=inv2.investigation_id,
            scope_sources=[APP_A], refresh_scope=True)
        rep2 = store.get_hit(refreshed.representative_ids[0])
        assert rep2.record_id == "P3"


# ---------- 运行入口 ----------

if __name__ == "__main__":
    import traceback

    classes = [TestHitEvidence, TestDisputedGroup,
               TestInvestigationSampling, TestInterleavedFlow]
    passed = failed = 0
    for cls in classes:
        instance = cls()
        for name in sorted(dir(instance)):
            if not name.startswith("test_"):
                continue
            try:
                getattr(instance, name)()
                passed += 1
                print(f"  PASS  test_investigation: {name}")
            except Exception:
                failed += 1
                print(f"  FAIL  test_investigation: {name}")
                traceback.print_exc()
    print(f"\ntest_investigation: {passed} passed, {failed} failed, "
          f"{passed + failed} total")
    sys.exit(1 if failed else 0)
