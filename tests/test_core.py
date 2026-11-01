"""Tests for beaconhunt. Run: python -m pytest -q"""

from __future__ import annotations

import random

import pytest

from beaconhunt.core import Connection, analyse, group_connections, score_group


def beacon(dest="c2.example.com", port=443, interval=60.0, n=30, jitter=0.0,
           size=512, start=0.0, seed=1):
    """Synthetic beacon: fixed interval, optional jitter, fixed payload."""
    rng = random.Random(seed)
    out = []
    t = start
    for _ in range(n):
        out.append(Connection(ts=t, dest=dest, port=port, bytes_out=size))
        t += interval + (rng.uniform(-jitter, jitter) if jitter else 0.0)
    return out


def human(dest="cdn.example.net", port=443, n=40, seed=2):
    """Bursty human traffic: heavy-tailed gaps, wildly varying sizes."""
    rng = random.Random(seed)
    out = []
    t = 0.0
    for _ in range(n):
        out.append(Connection(ts=t, dest=dest, port=port,
                              bytes_out=rng.randint(200, 900_000)))
        t += rng.expovariate(1 / 45.0) + rng.uniform(0, 300)
    return out


# --- the core claim -------------------------------------------------------

def test_perfect_beacon_scores_high():
    r = score_group("c2.example.com", 443, beacon())
    assert r.score >= 70, r.reasons
    assert r.confidence == "high"


def test_human_traffic_scores_low():
    r = score_group("cdn.example.net", 443, human())
    assert r.score < 45, r.reasons


def test_beacon_outranks_human():
    b = score_group("c2.example.com", 443, beacon())
    h = score_group("cdn.example.net", 443, human())
    assert b.score > h.score


# --- jitter behaviour -----------------------------------------------------

def test_small_jitter_still_detected():
    r = score_group("c2.example.com", 443, beacon(jitter=2.0))
    assert r.score >= 60, r.reasons


def test_large_jitter_reduces_score():
    tight = score_group("a", 443, beacon(jitter=0.5)).score
    loose = score_group("a", 443, beacon(jitter=25.0)).score
    assert loose < tight


def test_heavy_jitter_is_not_high_confidence():
    r = score_group("a", 443, beacon(jitter=40.0))
    assert r.confidence != "high"


# --- payload size ---------------------------------------------------------

def test_constant_payload_adds_evidence():
    fixed = score_group("a", 443, beacon(size=512)).score
    varied = score_group("a", 443, beacon(size=512)).score
    assert fixed == varied  # same input, deterministic

    rng = random.Random(9)
    noisy = [Connection(ts=c.ts, dest=c.dest, port=c.port,
                        bytes_out=rng.randint(100, 500_000)) for c in beacon()]
    assert score_group("a", 443, noisy).score < fixed


# --- edge cases -----------------------------------------------------------

def test_too_few_events_is_insufficient():
    r = score_group("a", 443, beacon(n=3))
    assert r.confidence == "insufficient"
    assert r.score == 0.0


def test_duplicate_timestamps_do_not_crash():
    conns = [Connection(ts=0.0, dest="a", port=443) for _ in range(20)]
    r = score_group("a", 443, conns)
    assert r.confidence == "insufficient"


def test_empty_group_is_insufficient():
    r = score_group("a", 443, [])
    assert r.confidence == "insufficient"


def test_score_is_bounded():
    for jitter in (0.0, 1.0, 10.0, 100.0):
        r = score_group("a", 443, beacon(jitter=jitter))
        assert 0.0 <= r.score <= 100.0


def test_unsorted_input_is_handled():
    conns = beacon()
    random.Random(3).shuffle(conns)
    r = score_group("c2.example.com", 443, conns)
    assert r.score >= 70


# --- grouping -------------------------------------------------------------

def test_grouping_separates_destinations():
    conns = beacon(dest="a") + beacon(dest="b", port=8080)
    groups = group_connections(conns)
    assert set(groups) == {("a", 443), ("b", 8080)}


def test_grouping_separates_ports_on_same_host():
    conns = beacon(dest="a", port=443) + beacon(dest="a", port=8443)
    assert len(group_connections(conns)) == 2


def test_analyse_sorts_by_score_descending():
    conns = beacon(dest="c2") + human(dest="cdn")
    results = analyse(conns, min_score=0)
    assert results[0].score >= results[-1].score


def test_analyse_respects_threshold():
    conns = beacon(dest="c2") + human(dest="cdn")
    results = analyse(conns, min_score=70)
    assert all(r.score >= 70 for r in results)
    assert any(r.dest == "c2" for r in results)


def test_analyse_returns_empty_when_nothing_qualifies():
    assert analyse(human(), min_score=95) == []


# --- explainability -------------------------------------------------------

def test_every_score_has_reasons():
    r = score_group("c2", 443, beacon())
    assert r.reasons
    assert all(isinstance(x, str) and x for x in r.reasons)


def test_as_dict_is_json_safe():
    import json
    r = score_group("c2", 443, beacon())
    json.dumps(r.as_dict())  # must not raise


def test_metrics_are_reported():
    r = score_group("c2", 443, beacon())
    assert "interval_cv" in r.metrics
    assert "events" in r.metrics
