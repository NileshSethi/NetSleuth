# NetSleuth Lite — Issues Found During Code Review

This file records discrepancies, limitations, and points of confusion found while
reading the code. Nothing in this list is a crash or a showstopper. They are noted
here so the report stays honest.

---

## Issue 1 — Evaluation function requires cleaned timestamps, not raw DataFrames

**Where:** `src/netsleuth/evaluation.py`, function `evaluate_all_scenarios`.

**What:** The function calls `run_all_detectors(df)` on the DataFrames passed to it.
If the caller passes the raw output of a `generate_scenario_*` function (which still has
string timestamps), `run_all_detectors` raises a `TypeError` because it tries to add a
`pd.Timedelta` to a string.

**Effect:** The function works correctly in `app.py` because `app.py` first passes the
CSV through `load_flows`, which converts timestamps. The bug only appears if a developer
calls `evaluate_all_scenarios` directly with raw DataFrames.

**Not fixed:** Listed here per task rules.

---

## Issue 2 — Scenario 3 exfiltration score reaches 60, not 80 (common misconception)

**Where:** `src/netsleuth/incidents.py`, `score_incident`.

**What:** 2,400,000 bytes (2.4 MB) is less than the 5 MB threshold for the +20 bonus but
greater than the 500 KB threshold for the +10 bonus. So the score is 50 + 10 = 60 (High),
not 80 (Critical). This is correct behaviour but may be surprising.

**Implication:** Scenario 3 is classified as "High" even though the data volume is large.
The score only reaches "Critical" if the attack is multi-stage AND the exfil volume
exceeds 5 MB (as in Scenario 4, which scores 90).

---

## Issue 3 — Benign traffic in Scenario 4 includes OUTBOUND flows to external sites

**Where:** `src/netsleuth/synthetic.py`, `generate_benign_flows`.

**What:** Benign web and email flows have `direction == "OUTBOUND"`. The exfiltration
detector also scans OUTBOUND flows. The benign flows stay below the 500 KB threshold
because each benign flow is at most 15,000 bytes. No false positive is raised, but
a developer must know this dependency to understand why the benign flows do not trigger
the exfiltration rule.

---

## Issue 4 — Host scan target string contains "hosts" not an IP

**Where:** `src/netsleuth/detectors.py`, `detect_host_scans`, line that sets `"target"`.

**What:** The target field is set to a string like `"12 hosts (port 445)"` instead of a
single IP address. This is intentional (a host scan hits many IPs), but it means the
target field has a different format than port scan and exfiltration alerts.

**Effect:** In `incidents.py`, `_assemble_incident` uses the check
`if "hosts" not in t` to exclude host-scan targets from the `targets` set. This is a
silent design choice with no comment explaining the reason.

---

## Issue 5 — graph.py uses a non-deterministic layout unless seed is fixed

**Where:** `src/netsleuth/graph.py`, `plot_graph`, call to `nx.spring_layout`.

**What:** The code passes `seed=42` to `spring_layout`, which makes the layout
deterministic. This is good. However, if the seed is ever removed, the graph positions
will change on every reload, which could confuse users comparing screenshots.

---

## Issue 6 — No rate limiting on forensic dossier export in app.py

**Where:** `app.py`, Tab 5.

**What:** The dossier is regenerated and re-rendered on every Streamlit rerun, which
happens whenever the user interacts with any widget. For large datasets this could cause
a noticeable delay. No caching or rate limiting is applied to the dossier generation.

---

## Issue 7 — evaluation.py returns precision=1.0 for Scenario 5 (0 TP, 0 FP, 0 FN)

**Where:** `src/netsleuth/evaluation.py`, `evaluate_single_scenario`.

**What:** When TP = 0, FP = 0, FN = 0 (benign baseline with zero attacks and zero alerts),
the formula `precision = 1.0 if (tp+fp)==0` and `recall = 1.0 if (tp+fn)==0` returns
1.0000 by convention. This is a standard convention in evaluation literature (undefined
precision is set to 1), but it can look misleading in a table.

---

*End of issues file.*
