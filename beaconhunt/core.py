"""Beaconing detection for C2 traffic analysis.

The premise: malware that calls home on a timer is statistically different from
a human browsing. A beacon has low jitter around a fixed interval and often
near-constant payload sizes. Human traffic is bursty and heavy-tailed.

This module scores each (destination, port) pair on those properties and
explains every point it awards, so an analyst can disagree with the reasoning
rather than trust a black box.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from typing import Iterable, Sequence

__all__ = [
    "Connection",
    "BeaconScore",
    "analyse",
    "score_group",
    "group_connections",
]


@dataclass(frozen=True)
class Connection:
    """A single outbound connection observation."""

    ts: float
    dest: str
    port: int
    bytes_out: int = 0
    bytes_in: int = 0


@dataclass
class BeaconScore:
    dest: str
    port: int
    count: int
    score: float
    confidence: str
    reasons: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "dest": self.dest,
            "port": self.port,
            "count": self.count,
            "score": round(self.score, 1),
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "metrics": {k: (round(v, 4) if isinstance(v, float) else v)
                        for k, v in self.metrics.items()},
        }


# --------------------------------------------------------------------------
# statistics helpers
# --------------------------------------------------------------------------

def _deltas(ts: Sequence[float]) -> list[float]:
    """Inter-arrival times, dropping non-positive gaps (duplicate timestamps)."""
    return [b - a for a, b in zip(ts, ts[1:]) if b > a]


def _cv(xs: Sequence[float]) -> float:
    """Coefficient of variation. Lower means more regular."""
    if not xs:
        return float("inf")
    mean = statistics.fmean(xs)
    if mean == 0:
        return float("inf")
    return statistics.pstdev(xs) / mean


def _mad(xs: Sequence[float]) -> float:
    """Median absolute deviation - robust to a single long gap."""
    if not xs:
        return 0.0
    med = statistics.median(xs)
    return statistics.median([abs(x - med) for x in xs])


def _autocorr_peak(xs: Sequence[float], max_lag: int | None = None) -> tuple[int, float]:
    """Strongest normalized autocorrelation of the interval series.

    A beacon whose interval drifts slowly still shows a strong peak at a short
    lag, which plain variance misses.
    """
    n = len(xs)
    if n < 8:
        return (0, 0.0)
    mean = statistics.fmean(xs)
    var = sum((x - mean) ** 2 for x in xs)
    if var == 0:
        return (0, 0.0)
    limit = max_lag or min(n // 2, 20)
    best_lag, best_val = 0, 0.0
    for lag in range(1, limit + 1):
        num = sum((xs[i] - mean) * (xs[i + lag] - mean) for i in range(n - lag))
        val = (num / (n - lag)) / (var / n)
        if val > best_val:
            best_lag, best_val = lag, val
    return (best_lag, best_val)


def _entropy(counts: Sequence[int]) -> float:
    """Shannon entropy of a size distribution, in bits."""
    total = sum(counts)
    if total <= 0:
        return 0.0
    ent = 0.0
    for c in counts:
        if c <= 0:
            continue
        p = c / total
        ent -= p * math.log2(p)
    return ent


# --------------------------------------------------------------------------
# grouping
# --------------------------------------------------------------------------

def group_connections(conns: Iterable[Connection]) -> dict[tuple[str, int], list[Connection]]:
    groups: dict[tuple[str, int], list[Connection]] = {}
    for c in conns:
        groups.setdefault((c.dest, c.port), []).append(c)
    for v in groups.values():
        v.sort(key=lambda c: c.ts)
    return groups


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------

MIN_EVENTS = 8


def score_group(dest: str, port: int, conns: Sequence[Connection]) -> BeaconScore:
    """Score one destination/port pair. Higher means more beacon-like."""
    conns = sorted(conns, key=lambda c: c.ts)
    n = len(conns)
    reasons: list[str] = []
    metrics: dict = {"events": n}

    if n < MIN_EVENTS:
        return BeaconScore(
            dest=dest, port=port, count=n, score=0.0, confidence="insufficient",
            reasons=[f"only {n} events; need {MIN_EVENTS} to judge periodicity"],
            metrics=metrics,
        )

    deltas = _deltas([c.ts for c in conns])
    if len(deltas) < MIN_EVENTS - 1:
        return BeaconScore(
            dest=dest, port=port, count=n, score=0.0, confidence="insufficient",
            reasons=["too many duplicate timestamps to measure intervals"],
            metrics=metrics,
        )

    score = 0.0

    # --- 1. interval regularity (0-40) -----------------------------------
    cv = _cv(deltas)
    metrics["interval_mean_s"] = statistics.fmean(deltas)
    metrics["interval_cv"] = cv
    if cv < 0.05:
        score += 40
        reasons.append(f"interval is near-constant (CV {cv:.3f}) - machine timer")
    elif cv < 0.15:
        score += 30
        reasons.append(f"interval is highly regular (CV {cv:.3f})")
    elif cv < 0.30:
        score += 18
        reasons.append(f"interval is fairly regular (CV {cv:.3f})")
    elif cv < 0.60:
        score += 6
        reasons.append(f"interval is loosely regular (CV {cv:.3f})")
    else:
        reasons.append(f"interval is irregular (CV {cv:.3f}) - consistent with human use")

    # --- 2. robust jitter (0-15) -----------------------------------------
    mad = _mad(deltas)
    mean = statistics.fmean(deltas)
    jitter = mad / mean if mean else float("inf")
    metrics["jitter_mad_ratio"] = jitter
    if jitter < 0.05:
        score += 15
        reasons.append(f"jitter is tiny (MAD/mean {jitter:.3f}) - classic sleep-loop")
    elif jitter < 0.15:
        score += 9
        reasons.append(f"jitter is small (MAD/mean {jitter:.3f})")
    elif jitter < 0.35:
        score += 3

    # --- 3. autocorrelation (0-15) ---------------------------------------
    lag, ac = _autocorr_peak(deltas)
    metrics["autocorr_lag"] = lag
    metrics["autocorr_peak"] = ac
    if ac > 0.7:
        score += 15
        reasons.append(f"strong periodicity at lag {lag} (r={ac:.2f})")
    elif ac > 0.4:
        score += 8
        reasons.append(f"moderate periodicity at lag {lag} (r={ac:.2f})")

    # --- 4. payload size regularity (0-20) -------------------------------
    sizes = [c.bytes_out for c in conns if c.bytes_out > 0]
    if len(sizes) >= MIN_EVENTS:
        size_cv = _cv(sizes)
        metrics["size_cv"] = size_cv
        if size_cv < 0.10:
            score += 20
            reasons.append(f"payload size is near-constant (CV {size_cv:.3f}) - fixed check-in")
        elif size_cv < 0.25:
            score += 12
            reasons.append(f"payload size is regular (CV {size_cv:.3f})")
        elif size_cv < 0.50:
            score += 5
        # entropy of the rounded size distribution
        buckets: dict[int, int] = {}
        for s in sizes:
            buckets[s // 16] = buckets.get(s // 16, 0) + 1
        ent = _entropy(list(buckets.values()))
        metrics["size_entropy_bits"] = ent
        if ent < 1.0:
            score += 5
            reasons.append(f"size distribution has low entropy ({ent:.2f} bits)")

    # --- 5. long-lived low-and-slow (0-10) -------------------------------
    span = conns[-1].ts - conns[0].ts
    metrics["span_s"] = span
    if span > 3600 and n >= 20:
        score += 10
        reasons.append(f"{n} events over {span/3600:.1f}h - low and slow")
    elif span > 1800:
        score += 5

    score = max(0.0, min(100.0, score))

    if score >= 70:
        confidence = "high"
    elif score >= 45:
        confidence = "medium"
    elif score >= 25:
        confidence = "low"
    else:
        confidence = "unlikely"

    return BeaconScore(
        dest=dest, port=port, count=n, score=score,
        confidence=confidence, reasons=reasons, metrics=metrics,
    )


def analyse(conns: Iterable[Connection], min_score: float = 25.0) -> list[BeaconScore]:
    """Score every destination/port pair, strongest first."""
    results = [
        score_group(dest, port, group)
        for (dest, port), group in group_connections(conns).items()
    ]
    results = [r for r in results if r.score >= min_score]
    results.sort(key=lambda r: r.score, reverse=True)
    return results
