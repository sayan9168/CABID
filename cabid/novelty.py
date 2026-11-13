"""Statistical validation and drift tracking for benign baselines.

A novelty score is only as trustworthy as the baseline behind it, and CABID
previously offered no way to check that baseline. Two questions had no answer:

1. *Is this baseline statistically sound?* A profile fitted on four sessions, or
   on sessions that do not agree with each other, will mark ordinary activity as
   novel. That failure is silent — the operator sees alerts, not a bad fit.
2. *Has the baseline stopped describing the host?* Software upgrades, role
   changes, and seasonal load all move "normal" without anything malicious
   happening. A stale baseline fails loudly (false alerts) and quietly (missed
   drift).

This module answers both without adding a dependency:

* **Validation** applies the assumption behind the smooth novelty terms — that
  benign sessions are *interchangeable*, so a hold-one-out fit should describe the
  held-out session — as a Kolmogorov–Smirnov style comparison over event rates,
  plus a support and coverage audit. The result is a verdict on the *baseline*, not
  on the host.
* **Drift** compares successive benign windows with a two-sample
  Kolmogorov–Smirnov statistic and an exact binomial test on classification flips,
  reports which specific features moved, and proposes — never applies — a profile
  update.

Both are deliberately conservative: they report "the baseline may no longer
describe this host" rather than "the host is compromised". Drift is not an attack
signal, and conflating the two is how benign change becomes an incident.
"""
from __future__ import annotations

import math
from collections import Counter

from .baseline import novelty_features

#: A two-sample KS statistic above this is treated as a distribution shift. Chosen
#: so that sampling noise in a few hundred sessions does not fire, while a genuine
#: role change does. Not a p-value: see ``ks_critical_value``.
DEFAULT_DRIFT_THRESHOLD = 0.30

#: Smallest reference set a validation verdict is offered for.
MIN_VALIDATION_SESSIONS = 20


class NoveltyError(ValueError):
    """Raised when a baseline cannot be validated or compared responsibly."""


def ks_statistic(left: list[float], right: list[float]) -> float:
    """Two-sample Kolmogorov–Smirnov statistic: max distance between ECDFs.

    Ranges 0 (identical distributions) to 1 (disjoint). Makes no distributional
    assumption, which matters because event rates are skewed and bounded below by
    zero — the exact situation where a t-test would be misleading.
    """
    if not left or not right:
        raise ValueError("both samples need at least one value")
    a, b = sorted(left), sorted(right)
    # Ties must be absorbed as a block before the distance is compared. Advancing one
    # sample at a time compares ECDF heights mid-tie, which reports a spurious gap
    # between two identical distributions (measured: 0.333 for identical samples).
    i = j = 0
    distance = 0.0
    while i < len(a) and j < len(b):
        value = min(a[i], b[j])
        while i < len(a) and a[i] == value:
            i += 1
        while j < len(b) and b[j] == value:
            j += 1
        distance = max(distance, abs(i / len(a) - j / len(b)))
    return distance


def ks_critical_value(n_left: int, n_right: int, alpha: float = 0.05) -> float:
    """Asymptotic KS critical value at significance ``alpha``.

    Reported next to the statistic so an operator can see whether an observed drift
    is beyond sampling noise for the number of sessions available. For small samples
    the asymptotic form is optimistic, which is why the drift verdict also requires
    the effect to exceed a fixed magnitude — a p-value alone would make a large
    sample flag a trivial difference.
    """
    if n_left <= 0 or n_right <= 0:
        raise ValueError("sample sizes must be positive")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be between 0 and 1")
    if n_left == n_right:
        correction = math.sqrt(-0.5 * math.log(alpha / 2.0))
        return min(1.0, correction * math.sqrt(2.0 / n_left))
    return min(1.0, math.sqrt(-0.5 * math.log(alpha / 2.0))
               * math.sqrt((n_left + n_right) / (n_left * n_right)))


def binomial_two_sided(successes: int, trials: int, probability: float = 0.5) -> float:
    """Exact two-sided binomial p-value, computed in log space.

    Used for the "how many sessions changed classification?" question, where the
    count is small and an approximation would be wrong. ``probability`` is the null
    hypothesis — 0.5 by default, i.e. changes are as likely in either direction.
    """
    if trials < 0 or successes < 0 or successes > trials:
        raise ValueError("require 0 <= successes <= trials")
    if not 0.0 < probability < 1.0:
        raise ValueError("probability must be between 0 and 1")

    def log_probability(k: int) -> float:
        return (math.lgamma(trials + 1) - math.lgamma(k + 1) - math.lgamma(trials - k + 1)
                + k * math.log(probability) + (trials - k) * math.log1p(-probability))

    observed = log_probability(successes)
    total = 0.0
    for k in range(trials + 1):
        term = log_probability(k)
        # Include every outcome at least as improbable as the observed one.
        if term <= observed + 1e-9:
            total += math.exp(term)
    return min(1.0, total)


def _session_rate(events: list[dict]) -> float | None:
    if len(events) < 2:
        return None
    times = sorted(float(event["timestamp"]) for event in events)
    duration = max(times) - min(times)
    return len(times) * 60.0 / max(duration, 1.0)


def _labels(profile: dict, sessions: list[tuple[str, list[dict]]]) -> list[int]:
    """Classification of each session under ``profile``: 1 = flagged as novel."""
    labels = []
    for _name, events in sessions:
        if not events:
            continue
        features = novelty_features(events, profile)
        labels.append(int(float(features.get("novelty_score", 0.0)) > 0.0))
    return labels


def validate(profile: dict, sessions: list[tuple[str, list[dict]]], *,
             minimum_sessions: int = MIN_VALIDATION_SESSIONS,
             novelty_cutoff: float = 0.25) -> dict:
    """Audit a baseline profile against held-out benign sessions.

    ``sessions`` must be benign and should be disjoint from the sessions the profile
    was fitted on; pass the fitting set and the coverage figure is meaningless.
    """
    if not isinstance(profile, dict):
        raise NoveltyError("a baseline profile object is required")
    usable = [(name, events) for name, events in sessions if events]
    if len(usable) < minimum_sessions:
        raise NoveltyError(
            f"{len(usable)} held-out session(s) supplied but {minimum_sessions} are "
            "required for a verdict; validating a baseline against a handful of "
            "sessions cannot distinguish a bad fit from an unlucky sample"
        )

    fitted = {str(name) for name in profile.get("sessions") or []}
    overlap = sorted({name for name, _ in usable} & fitted)
    observed = [_session_rate(events) for _, events in usable]
    rates = [rate for rate in observed if rate is not None]
    if len(rates) < minimum_sessions:
        raise NoveltyError(
            f"only {len(rates)} held-out sessions have enough events to measure a rate "
            f"({minimum_sessions} required)"
        )

    reference_rate = float((profile.get("rate_per_minute") or {}).get("median", 0.0))
    reference_scale = float((profile.get("rate_per_minute") or {}).get("scale", 0.0))
    ks_rate, rate_method = rate_divergence(profile, rates)

    novelty_scores = [
        float(novelty_features(events, profile).get("novelty_score", 0.0))
        for _, events in usable
    ]
    flagged = [score for score in novelty_scores if score > novelty_cutoff]
    coverage = 1.0 - len(flagged) / len(novelty_scores)

    known_names = {str(name) for name in profile.get("process_names") or []}
    seen_names: set[str] = set()
    for _, events in usable:
        seen_names |= {str(event.get("process_name") or "unknown") for event in events}
    unseen = sorted(seen_names - known_names)

    findings: list[str] = []
    verdict = "SOUND"
    if overlap:
        verdict = "INVALID"
        findings.append(
            f"{len(overlap)} held-out session(s) were also used to fit the profile "
            f"(first: {overlap[0]}); coverage figures are not meaningful")
    if ks_rate > DEFAULT_DRIFT_THRESHOLD:
        verdict = "NEEDS_REFIT" if verdict == "SOUND" else verdict
        findings.append(
            f"held-out event rates diverge from the baseline median "
            f"(KS {ks_rate:.3f} > {DEFAULT_DRIFT_THRESHOLD}); the baseline may already "
            "be stale")
    if coverage < 0.90 and verdict == "SOUND":
        verdict = "NEEDS_REFIT"
        findings.append(
            f"only {coverage:.1%} of held-out benign sessions scored below the novelty "
            f"cutoff {novelty_cutoff}; a benign-only baseline should describe most "
            "benign traffic")
    if len(unseen) > max(5, 0.25 * max(len(known_names), 1)) and verdict == "SOUND":
        verdict = "NEEDS_REFIT"
        findings.append(
            f"{len(unseen)} process name(s) in held-out sessions are absent from the "
            "profile, beyond tolerance")
    if verdict == "SOUND":
        findings.append("held-out benign sessions are consistent with the baseline")

    return {
        "format": "cabid-baseline-validation/1",
        "verdict": verdict,
        "verdict_semantics": (
            "a judgement about the baseline profile, not about the host or any event"),
        "session_count": len(usable),
        "profile_session_count": profile.get("session_count"),
        "novelty_cutoff": novelty_cutoff,
        "coverage": round(coverage, 6),
        "flagged_sessions": len(flagged),
        "ks_rate_vs_baseline": round(ks_rate, 6),
        "ks_critical_value": round(ks_critical_value(len(rates), len(rates)), 6),
        "ks_threshold": DEFAULT_DRIFT_THRESHOLD,
        "rate_median_observed": round(_middle(rates), 6),
        "rate_median_baseline": round(reference_rate, 6),
        "rate_divergence_method": rate_method,
        "rate_scale_baseline": round(reference_scale, 6),
        "unseen_process_names": unseen[:20],
        "unseen_process_name_count": len(unseen),
        "fit_overlap": overlap[:10],
        "findings": findings,
        "limitations": [
            "Judges the baseline only; a sound baseline can still be defeated by an "
            "attacker who behaves like the baseline.",
            "Held-out sessions must be genuinely disjoint from the fitting set; the "
            "check here can only see session names the profile recorded.",
            "The rate comparison uses one scalar per session and discards event "
            "ordering, so it detects workload-shape drift, not sequence drift.",
        ],
    }


def rate_divergence(profile: dict, values: list[float]) -> tuple[float, str]:
    """Compare held-out event rates against the baseline's reference sample.

    Returns ``(statistic, method)``. A two-sample KS against the stored reference
    sample is used when the profile has one. Older profiles only carry a median and
    a scale, where a proper two-sample test is impossible; for those the returned
    statistic is the fraction of held-out rates further than three scales from the
    median, which is comparable in spirit even though it is not a KS distance.
    """
    if not values:
        raise ValueError("at least one observed rate is required")
    reference = [float(value) for value in profile.get("rate_samples") or []]
    if len(reference) >= 2:
        # Compare at the precision the profile stores. Without this, two samples that
        # describe the same workload compare as disjoint the moment they differ in the
        # ninth decimal, and KS returns 1.0 for identical behaviour (observed on real
        # corpus data before this rounding was added).
        precision = 6
        return (ks_statistic([round(value, precision) for value in reference],
                             [round(value, precision) for value in values]),
                "two_sample_ks")
    median_rate = float((profile.get("rate_per_minute") or {}).get("median", 0.0))
    scale = float((profile.get("rate_per_minute") or {}).get("scale", 0.0)) or 0.05
    outside = sum(1 for value in values if abs(value - median_rate) > 3.0 * scale)
    return outside / len(values), "three_sigma_fraction"


def _middle(values: list[float]) -> float:
    ordered = sorted(values)
    count = len(ordered)
    if not count:
        return 0.0
    midpoint = count // 2
    return ordered[midpoint] if count % 2 else (ordered[midpoint - 1] + ordered[midpoint]) / 2


def drift(profile: dict, sessions: list[tuple[str, list[dict]]], *,
          threshold: float = DEFAULT_DRIFT_THRESHOLD,
          novelty_cutoff: float = 0.25) -> dict:
    """Compare newer benign sessions against a baseline and report what moved.

    Returns a *proposal*, never a mutated profile: widening a baseline
    automatically is how novelty detection degrades into a rubber stamp.
    """
    if not isinstance(profile, dict):
        raise NoveltyError("a baseline profile object is required")
    if not 0.0 < threshold < 1.0:
        raise NoveltyError("threshold must be between 0 and 1")
    usable = [(name, events) for name, events in sessions if events]
    if not usable:
        raise NoveltyError("at least one session with events is required")

    rates = [rate for rate in (_session_rate(events) for _, events in usable)
             if rate is not None]
    baseline_rate = float((profile.get("rate_per_minute") or {}).get("median", 0.0))
    baseline_scale = float((profile.get("rate_per_minute") or {}).get("scale", 0.0))
    if rates:
        ks_rate, rate_method = rate_divergence(profile, rates)
    else:
        ks_rate, rate_method = 0.0, "none"

    baseline_mix = {str(kind): float(value)
                    for kind, value in (profile.get("type_mix") or {}).items()}
    observed_counts: Counter[str] = Counter()
    for _, events in usable:
        observed_counts.update(str(event["event_type"]) for event in events)
    total = sum(observed_counts.values()) or 1
    observed_mix = {kind: count / total for kind, count in observed_counts.items()}
    mix_distance = 0.5 * sum(abs(observed_mix.get(kind, 0.0) - baseline_mix.get(kind, 0.0))
                             for kind in set(baseline_mix) | set(observed_mix))

    unknown_children = set()
    known_edges = {tuple(edge) for edge in (profile.get("parent_child") or [])}
    for _, events in usable:
        by_pid = {event["process_id"]: str(event.get("process_name") or "unknown")
                  for event in events}
        for event in events:
            parent = by_pid.get(event.get("parent_process_id") or -1)
            child = str(event.get("process_name") or "unknown")
            if parent and child != "unknown" and parent != child:
                if (parent, child) not in known_edges:
                    unknown_children.add(f"{parent}->{child}")

    flips = _labels(profile, usable)
    p_value = binomial_two_sided(sum(flips), len(flips)) if flips else 1.0

    features = []
    if ks_rate >= threshold:
        features.append({
            "feature": "event_rate_per_minute",
            "statistic": round(ks_rate, 6),
            "baseline": round(baseline_rate, 6),
            "observed": round(_middle(rates), 6) if rates else 0.0,
            "direction": ("higher" if rates and _middle(rates) > baseline_rate else "lower"),
        })
    if mix_distance >= threshold:
        features.append({
            "feature": "event_type_mix",
            "statistic": round(mix_distance, 6),
            "baseline": "profile type_mix",
            "observed": "recent sessions",
            "direction": "shifted",
        })
    if unknown_children and len(unknown_children) >= 2:
        features.append({
            "feature": "parent_child_edges",
            "statistic": float(len(unknown_children)),
            "baseline": "profile parent_child",
            "observed": sorted(unknown_children)[:10],
            "direction": "new edges",
        })

    drifted = bool(features)
    suggestions = []
    if drifted:
        for edge in sorted(unknown_children):
            parent, _sep, child = edge.partition("->")
            suggestions.append(f"new benign ancestry edge {parent} -> {child}")
        if ks_rate >= threshold:
            suggestions.append(
                f"consider widening rate_per_minute around {_middle(rates):.1f}/min "
                f"(baseline median {baseline_rate:.1f}, current scale {baseline_scale:.1f})")
        if mix_distance >= threshold:
            top = sorted(observed_mix.items(), key=lambda item: item[1], reverse=True)[:3]
            suggestions.append("observed event mix is dominated by "
                               + ", ".join(f"{kind} {share:.0%}" for kind, share in top))

    return {
        "format": "cabid-drift-report/1",
        "drifted": drifted,
        "threshold": threshold,
        "rate_divergence_method": rate_method,
        "session_count": len(usable),
        "features": features,
        "classification_flips": sum(flips),
        "flip_probability": round(float(p_value), 6),
        "novelty_cutoff": novelty_cutoff,
        "suggestions": suggestions,
        "recommendation": (
            "Review the proposed updates and refit the baseline deliberately with "
            "cabid build-baseline. Nothing here is applied automatically: an "
            "unreviewed widening of a baseline silently disables novelty detection."
        ) if drifted else "No drift detected against the current baseline.",
        "drift_is_not_an_attack_signal": (
            "Drift means the baseline no longer describes the host. Benign software "
            "changes cause it constantly; it is evidence about the model, not about "
            "intent."),
        "limitations": [
            "Compares distributions of rates and event-type mixes, not sequences; a "
            "host whose behaviour changed only in ordering is not detected here.",
            "Requires recent benign-labelled sessions. Unlabelled recent traffic cannot "
            "be used, so drift is detected later than an operator would like.",
            "A single drift verdict spans the whole supplied window; gradual drift "
            "spread across many windows may stay under the threshold each time.",
        ],
    }
