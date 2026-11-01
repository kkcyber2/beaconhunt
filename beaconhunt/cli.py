"""beaconhunt CLI - score connection logs for C2 beaconing."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from .core import Connection, analyse


def load_csv(path: Path) -> list[Connection]:
    """Read connections from CSV.

    Required columns: ts, dest, port. Optional: bytes_out, bytes_in.
    `ts` may be epoch seconds or an ISO-8601 timestamp.
    """
    conns: list[Connection] = []
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise ValueError("empty CSV")
        missing = {"ts", "dest", "port"} - set(reader.fieldnames)
        if missing:
            raise ValueError(f"CSV missing required column(s): {', '.join(sorted(missing))}")
        for i, row in enumerate(reader, start=2):
            try:
                conns.append(
                    Connection(
                        ts=_parse_ts(row["ts"]),
                        dest=row["dest"].strip(),
                        port=int(row["port"]),
                        bytes_out=int(row.get("bytes_out") or 0),
                        bytes_in=int(row.get("bytes_in") or 0),
                    )
                )
            except (ValueError, KeyError) as exc:
                raise ValueError(f"{path}:{i}: {exc}") from exc
    return conns


def _parse_ts(raw: str) -> float:
    raw = raw.strip()
    try:
        return float(raw)
    except ValueError:
        pass
    from datetime import datetime, timezone

    text = raw.replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def render_text(results) -> str:
    if not results:
        return "No beacon-like destinations found above the threshold.\n"
    lines = []
    for r in results:
        lines.append(f"[{r.score:5.1f}] {r.confidence.upper():12s} {r.dest}:{r.port}  ({r.count} events)")
        for reason in r.reasons:
            lines.append(f"         - {reason}")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="beaconhunt",
        description="Detect C2 beaconing in connection logs. Defensive analysis only.",
    )
    p.add_argument("csv", type=Path, help="CSV with columns: ts,dest,port[,bytes_out,bytes_in]")
    p.add_argument("--min-score", type=float, default=25.0, help="report threshold (default 25)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    p.add_argument("--fail-on", type=float, default=None,
                   help="exit 1 if any destination scores at or above this value")
    args = p.parse_args(argv)

    try:
        conns = load_csv(args.csv)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    results = analyse(conns, min_score=args.min_score)

    if args.json:
        print(json.dumps([r.as_dict() for r in results], indent=2))
    else:
        print(render_text(results))

    if args.fail_on is not None and any(r.score >= args.fail_on for r in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
