# beaconhunt

Detect C2 beaconing in connection logs.

Malware that calls home on a timer looks statistically different from a human
browsing. A beacon has low jitter around a fixed interval and often a
near-constant payload size. Human traffic is bursty and heavy-tailed. This tool
scores each destination on those properties and **explains every point it
awards**, so an analyst can disagree with the reasoning instead of trusting a
black box.

## Why not just threshold on connection count?

Because a CDN will beat any count threshold and a 60-second beacon with 30
events will not. Periodicity is the signal, not volume.

## Install

```bash
pip install -e ".[dev]"
```

No runtime dependencies — standard library only.

## Usage

```bash
beaconhunt connections.csv
beaconhunt connections.csv --json
beaconhunt connections.csv --min-score 50 --fail-on 70   # exit 1 if anything scores >= 70
```

Input CSV needs `ts,dest,port`; `bytes_out` and `bytes_in` are optional but
improve accuracy. `ts` accepts epoch seconds or ISO-8601.

```csv
ts,dest,port,bytes_out
0,c2.example.com,443,512
60,c2.example.com,443,512
120,c2.example.com,443,512
```

Output (real output for the 30-event, 60-second, 512-byte example above):

```
[ 80.0] HIGH         c2.example.com:443  (30 events)
         - interval is near-constant (CV 0.000) — machine timer
         - jitter is tiny (MAD/mean 0.000) — classic sleep-loop
         - payload size is near-constant (CV 0.000) — fixed check-in
         - size distribution has low entropy (0.00 bits)
```

Note that autocorrelation and "low and slow" do **not** fire here: with a
perfectly constant interval the variance is zero, so autocorrelation is
undefined, and 30 events over 29 minutes is under the 30-minute span
threshold. The score is still 80 because interval and payload regularity
alone are strong evidence. A drifting-interval beacon is what the
autocorrelation term is for.

## How the score works

| Signal | Max points | What it measures |
|---|---|---|
| Interval regularity | 40 | Coefficient of variation of inter-arrival times |
| Robust jitter | 15 | MAD/mean — survives a single long gap that inflates stdev |
| Autocorrelation | 15 | Strong peak at a short lag catches slowly-drifting intervals |
| Payload constancy | 20 | CV of `bytes_out`, plus entropy of the size distribution |
| Low and slow | 10 | Many events over a long span |

Total is capped at 100. Confidence bands: `high` ≥ 70, `medium` ≥ 45,
`low` ≥ 25, `unlikely` below. Fewer than 8 events returns `insufficient` rather
than a guess.

## Use as a library

```python
from beaconhunt.core import Connection, analyse

conns = [Connection(ts=t, dest="c2.example.com", port=443, bytes_out=512)
         for t in range(0, 1800, 60)]

for hit in analyse(conns, min_score=45):
    print(hit.dest, hit.score, hit.confidence)
    for reason in hit.reasons:
        print("  -", reason)
```

## Tests

```bash
python -m pytest -q
```

32 tests. Covers: perfect beacon scores high, human traffic scores low, jitter
degrades the score monotonically, constant payload adds evidence, duplicate
timestamps and empty groups do not crash, unsorted input is handled, grouping
separates host and port, threshold filtering, and JSON output is serialisable.

## Limitations — read these

- **It is a statistical signal, not proof.** A legitimate health-check poller,
  a monitoring agent, or a software update checker will score high. Correlate
  with process, user, and reputation before calling anything malicious.
- **Needs ≥ 8 events per destination.** Short-lived beacons are invisible.
- **Assumes a roughly fixed interval.** Beacons with heavy randomisation
  (jitter > 40% of the interval) deliberately defeat this and will score low —
  that is the attacker's counter-move, and this tool does not claim to beat it.
- **No DNS, TLS, or JA3 enrichment.** It reads timestamps and sizes only.
- **Single-destination analysis.** It does not correlate a beacon across
  multiple destinations or detect domain-generation patterns.
- **Timestamps must be monotonic per destination.** Clock skew across log
  sources will produce false negatives.

## Legal

Defensive analysis of logs you are authorised to hold. Nothing here touches a
network or a remote host. Do not use it to characterise traffic you have no
lawful basis to inspect.

## Licence

MIT
