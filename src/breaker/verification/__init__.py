"""Shared verification primitives for Breaker.

This package holds the logic that Breaker's workflow-specific verification harnesses used to repeat:
effect observation, run-attributed persistence read-back, effect/state coherence, failure classification,
retry/replay provenance, case sequencing, regression export and the public evidence summary.

Core principle (unchanged): **authored expectation + independent observation + deterministic verdict.**
Nothing here generates a verdict from a model. Every primitive is a pure function over observations, so a
verdict can always be traced back to the values that produced it.

Design rules this package follows:

* Failure classes are explicit and orthogonal (:mod:`breaker.verification.taxonomy`). A harness problem never
  becomes a product verdict.
* Effects are observed through adapters that only know how to *read*. No adapter writes to a provider, and
  no provider API is invented for a provider Breaker has not actually exercised.
* Persistence assertions are run-attributed, strongest identity first (``run_id`` → ``execution_id`` →
  stable identity → precise time window). Broad time windows are never the primary evidence.
* Everything that reasons about old artifacts is additive: schemas carry versions, and superseded attempts
  stay visible.
"""
from __future__ import annotations

from breaker.verification.checks import Check, CheckSet
from breaker.verification.coherence import (
    CoherenceFinding,
    CoherenceRule,
    Surface,
    check_coherence,
    declared_success_vs_effect_ledger,
    object_claim_vs_provider_readback,
    terminal_vs_persistence,
)
from breaker.verification.effects import (
    CallableEffectAdapter,
    DataTableEffectAdapter,
    EffectAdapter,
    EffectKind,
    EffectWindow,
    HttpApiAdapter,
    ProviderObjectAdapter,
    SmtpSinkAdapter,
    before_after_counts,
    delta,
    did_not_happen,
    duplicate_rerun_produced_no_second_effect,
    failure_did_not_record_false_success,
    happened_exactly_once,
    message_read_back,
    object_read_back,
    observe,
)
from breaker.verification.jsonfields import (
    StoredListState,
    assert_items_match_expected,
    assert_parsed_is_array,
    assert_single_serialization,
    canonical_list,
    inspect_stored_list,
    valid_json_text,
)
from breaker.verification.persistence import (
    AttributedRows,
    AttributionMatch,
    AttributedStore,
    DataTableStore,
    RunAttribution,
    RowsFromCallable,
    StoreReader,
    exact_row_count,
    forbidden_values,
    no_duplicate_row,
    no_stale_row_contamination,
    required_fields,
    rows_written_by_this_run,
    state_before_after,
    updated_in_place,
)
from breaker.verification.public_summary import (
    PUBLIC_SUMMARY_SCHEMA_VERSION,
    EffectDisclosure,
    build_public_summary,
    critical_from_checks,
    write_public_summary,
)
from breaker.verification.regression_export import (
    REGRESSION_CANDIDATE_SCHEMA_VERSION,
    build_regression_candidate,
    from_case_report,
    write_regression_candidate,
)
from breaker.verification.replay import (
    Attempt,
    RateWindowPacer,
    ReplayLedger,
    RetryPolicy,
    run_with_replay,
    wait_for_execution_visibility,
)
from breaker.verification.sequence import (
    CaseSequence,
    ResetPolicy,
    group_by_fixture_scope,
    resolve_order,
    sequence_from_metadata,
    validate_sequence,
)
from breaker.verification.taxonomy import (
    VERDICT_DEFINITIONS,
    Signal,
    Verdict,
    classify_exception,
    classify_signals,
    counts_as_dynamic_proof,
    is_blocking,
    is_product_defect,
    summarize_verdicts,
)

__all__ = [
    "Attempt", "AttributedRows", "AttributedStore", "AttributionMatch", "CallableEffectAdapter",
    "CaseSequence", "Check", "CheckSet", "CoherenceFinding", "CoherenceRule", "DataTableEffectAdapter",
    "DataTableStore", "EffectAdapter", "EffectDisclosure", "EffectKind", "EffectWindow",
    "HttpApiAdapter", "ProviderObjectAdapter", "PUBLIC_SUMMARY_SCHEMA_VERSION", "RateWindowPacer",
    "REGRESSION_CANDIDATE_SCHEMA_VERSION", "ReplayLedger", "ResetPolicy", "RetryPolicy",
    "RowsFromCallable", "RunAttribution", "Signal", "SmtpSinkAdapter", "StoredListState", "StoreReader",
    "Surface", "VERDICT_DEFINITIONS", "Verdict", "assert_items_match_expected", "assert_parsed_is_array",
    "assert_single_serialization", "before_after_counts", "build_public_summary", "build_regression_candidate",
    "canonical_list", "check_coherence", "classify_exception", "classify_signals",
    "counts_as_dynamic_proof", "critical_from_checks", "declared_success_vs_effect_ledger", "delta",
    "did_not_happen", "duplicate_rerun_produced_no_second_effect", "exact_row_count",
    "failure_did_not_record_false_success", "forbidden_values", "from_case_report",
    "group_by_fixture_scope", "happened_exactly_once", "inspect_stored_list", "is_blocking",
    "is_product_defect", "message_read_back", "no_duplicate_row", "no_stale_row_contamination",
    "object_claim_vs_provider_readback", "object_read_back", "observe", "required_fields",
    "resolve_order", "rows_written_by_this_run", "run_with_replay", "sequence_from_metadata",
    "state_before_after", "summarize_verdicts", "terminal_vs_persistence", "updated_in_place",
    "validate_sequence", "valid_json_text", "wait_for_execution_visibility",
    "write_public_summary", "write_regression_candidate",
]
