"""Tests for the beaconhunt CLI."""

from __future__ import annotations

import json

import pytest

from beaconhunt.cli import _parse_ts, load_csv, main


def write(tmp_path, text, name="conns.csv"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


BEACON_CSV = "ts,dest,port,bytes_out\n" + "".join(
    f"{i*60},c2.example.com,443,512\n" for i in range(30)
)


def _human_csv(n=40, seed=7):
    """Bursty human traffic: heavy-tailed gaps, wildly varying sizes.

    Built with a seeded RNG rather than arithmetic, because an arithmetic
    sequence is itself regular and would score as a weak beacon.
    """
    import random

    rng = random.Random(seed)
    rows, t = [], 0.0
    for _ in range(n):
        rows.append(f"{t:.3f},cdn.example.net,443,{rng.randint(200, 900_000)}")
        t += rng.expovariate(1 / 45.0) + rng.uniform(0, 300)
    return "ts,dest,port,bytes_out\n" + "\n".join(rows) + "\n"


HUMAN_CSV = _human_csv()


def test_load_csv_reads_rows(tmp_path):
    conns = load_csv(write(tmp_path, BEACON_CSV))
    assert len(conns) == 30
    assert conns[0].dest == "c2.example.com"
    assert conns[0].port == 443


def test_load_csv_optional_columns_default_to_zero(tmp_path):
    conns = load_csv(write(tmp_path, "ts,dest,port\n0,a,443\n60,a,443\n"))
    assert conns[0].bytes_out == 0


def test_load_csv_rejects_missing_columns(tmp_path):
    with pytest.raises(ValueError, match="missing required column"):
        load_csv(write(tmp_path, "ts,dest\n0,a\n"))


def test_load_csv_reports_bad_row_number(tmp_path):
    with pytest.raises(ValueError, match=":3:"):
        load_csv(write(tmp_path, "ts,dest,port\n0,a,443\n60,a,notaport\n"))


def test_parse_ts_accepts_epoch():
    assert _parse_ts("1700000000") == 1700000000.0


def test_parse_ts_accepts_iso_z():
    assert _parse_ts("2026-11-01T00:00:00Z") == _parse_ts("2026-11-01T00:00:00+00:00")


def test_cli_text_output_flags_beacon(tmp_path, capsys):
    rc = main([str(write(tmp_path, BEACON_CSV))])
    out = capsys.readouterr().out
    assert rc == 0
    assert "c2.example.com:443" in out
    assert "HIGH" in out


def test_cli_json_output_is_valid(tmp_path, capsys):
    rc = main([str(write(tmp_path, BEACON_CSV)), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload[0]["dest"] == "c2.example.com"
    assert payload[0]["score"] >= 70


def test_cli_fail_on_triggers_exit_1(tmp_path):
    assert main([str(write(tmp_path, BEACON_CSV)), "--fail-on", "70"]) == 1


def test_cli_fail_on_does_not_trigger_below_threshold(tmp_path):
    assert main([str(write(tmp_path, HUMAN_CSV)), "--fail-on", "70"]) == 0


def test_cli_missing_file_exits_2(tmp_path, capsys):
    rc = main([str(tmp_path / "nope.csv")])
    assert rc == 2
    assert "error:" in capsys.readouterr().err


def test_cli_clean_log_says_so(tmp_path, capsys):
    rc = main([str(write(tmp_path, HUMAN_CSV))])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No beacon-like destinations" in out
