# agent-permission-audit

Score how far an AI agent's tool permissions drift from least privilege. You give it a tool manifest (tools x operations) and an allow/deny policy; it classifies every `(tool, operation)` pair as allowed, denied, or unreviewed, weights the unreviewed surface by risk, and returns a 0-100 score with concrete tightening suggestions. Pure Python, standard library only, fully offline.

## Problem

Agent frameworks let you grant tools like `fs.write` or `shell.exec`, and policies grow by accretion: one wildcard here, an old allow rule there. After a few weeks nobody can answer the only question that matters — *of everything this agent could do, what has actually been decided, and what is silently open?* Audit reports rarely exist because gathering them means reading JSON by hand and cross-referencing a manifest.

## How it works

1. **Manifest**: a JSON object listing tools and their operations, e.g. `{"tools": [{"name": "shell", "ops": ["exec"]}]}.
2. **Policy**: allow/deny entries written as `"tool:op"` strings; either side may be `*` (`fs:*`, `*:read`, `*:*`).
3. **Classification**: every manifest pair is matched against deny rules first, then allow rules, then falls to `unreviewed`.
4. **Scoring**: operations carry fixed risk weights (`exec` 4, `write` 3, `network` 3, `read` 1). The score is `100 - risk-weighted unreviewed percentage`, so leaving `read` open costs far less than leaving `exec` open.
5. **Recommendations**: the report lists up to five highest-weight undecided pairs and redundant allow rules covered by broader ones.

## Quickstart

```bash
# ~1 min total
python agent_permission_audit.py audit --manifest manifest.json --policy policy.json
python agent_permission_audit.py audit --manifest manifest.json --policy policy.json --json
python agent_permission_audit.py audit --manifest manifest.json --policy policy.json --min-score 90
```

`--min-score 90` exits 1 when the score is below 90, so you can gate CI on it.

## Why not X

- **sg4tech/ai-agents-permission-audit** — audits *Claude Code session history* against `.claude/settings.local.json`: which commands ran, how they were approved, which patterns to add. It works at the session-replay layer; there is no manifest-level (tools x operations) scoring, and it is Claude-Code-specific.
- **yanqr213/agent-permission-auditor** — targets CI/agent permissions and emits SARIF/CSV; the focus is file-system and CI rule reporting rather than a weighted (tool, op) least-privilege score.
- **Cloud IAM analyzers** (AWS IAM Access Analyzer and friends) — excellent, but scoped to cloud resource policies, not agent tool manifests, and none run offline on a two-file input.
- **Manual review** — works once, drifts immediately; this tool is designed to be re-run on every policy change.

## How this differs from ai-agents-permission-audit

The closest anchor, `sg4tech/ai-agents-permission-audit`, works from the other side of the glass: it parses Claude Code JSONL session logs, infers how each `Bash` invocation was approved ("auto / user / denied" via a 2-second time-delta heuristic), and suggests allow patterns ranked by how many historical commands they would unblock — its README states the goal as seeing "which commands from your session history are not covered by your current allow rules". That is retrospective coverage of what *happened*. This repo does the complementary layer: given a declarative manifest of what the agent *could* do, it scores the decided-vs-open permission surface before anything runs, weighted by operation risk, with no dependence on any specific agent harness or session store. One is history-driven pattern mining; the other is manifest-driven surface scoring.

## Performance

[Measured] on Windows 10 Pro, Python 3.11, 2026-10-13. A 500-tool manifest (2,000 pairs, 500 allow rules, 1 deny rule) audits in **119.5 ms per run** (1.195 s for 10 runs). Reproduce:

```bash
python -c "import time,agent_permission_audit as m; man={'tools':[{'name':'t%d'%i,'ops':['read','write','exec','network']} for i in range(500)]}; pol={'allow':['t%d:read'%i for i in range(500)],'deny':['*:exec']}; t0=time.perf_counter(); [m.audit(man,pol) for _ in range(10)]; print(time.perf_counter()-t0)"
```

Typical agent manifests (5-50 tools) audit in under 5 ms [Measured].

## Minimal Fallback

No Python available on the audit host? Copy both JSON files into a spreadsheet: rows are `(tool, op)` pairs, mark each allowed/denied, and count unmarked rows weighted by the same risk table (exec 4, write 3, network 3, read 1). The score formula is one line: `100 * (1 - weighted_unreviewed / weighted_total)`.

## Design Trade-offs

- **Fixed risk weights over learned ones** — predictable and explainable beats tunable-but-mysterious. Weights are constants in the source, one line to change.
- **Wildcard policy syntax over regex** — `tool:op` with `*` covers 95% of real policies; regex would invite ReDoS and unreadable audits.
- **Deny-wins precedence** — matches the intuition most policy systems converge on; no override semantics are supported.
- **Score penalizes only unreviewed pairs, not denies** — an aggressive deny-everything policy scores 100; the tool optimizes for explicitness, not for capability.

## Limits & Second-order Effects

- The manifest is trusted input: if the manifest lies, the audit lies (garbage in, confident garbage out).
- A high score can create false comfort — explicit-but-wrong allows (e.g. `*:exec` allowed) still score 100. Read the report, not just the grade.
- CI gating on `--min-score` invites gaming: teams may delete risky tools from the manifest instead of deciding them.
- Weight values encode one team's risk intuition; another org may reasonably weigh `network` above `write`.

## FAQ

**When NOT to use this?**
When you need runtime enforcement or command-level analysis (e.g. whether `git push` is covered by `Bash(git *)` compound-command semantics). This tool audits declarative surface, not execution traces — use sg4tech/ai-agents-permission-audit for the latter.

**Does it talk to any agent framework?**
No. It reads two JSON files. Manifest/policy extraction from specific harnesses is intentionally out of scope.

**Why is a deny-only policy score 100?**
Because the score measures *explicitness of decisions*, not safety of outcomes. Denying everything is fully explicit.

**Can operations be arbitrary strings?**
Yes. Known ops get the fixed weights; unknown ops default to weight 2.

## Core Assumptions

- [A1] Tool capabilities can be reasonably modeled as a small set of operations (read/write/exec/network). Confidence: High.
- [A2] Teams will act on a scored, ranked list faster than on an unsorted allow/deny dump. Confidence: High.
- [A3] Fixed risk weights are stable enough across orgs to be useful defaults. Confidence: Medium — weights are exposed for a reason.
- [A4] Manifests and policies live as or can be exported to JSON. Confidence: High for JSON-native harnesses; Medium otherwise.

Confidence in the core mechanism (surface classification + weighted scoring): High. As of 2026-10-13.

## License

MIT — see [LICENSE](LICENSE). Contact: hcac4735@agent.qq.com

---

Part of the [zhengming-toolbox](https://github.com/chenhz01/zhengming-toolbox) — 105 purpose-built AI-engineering tools across neglected niches.

Related tools: [agent-trace-compression](https://github.com/chenhz01/agent-trace-compression) · [memory-expiry-policy](https://github.com/chenhz01/memory-expiry-policy) · [instruction-conflict-detector](https://github.com/chenhz01/instruction-conflict-detector)
