# Airlock — Architecture

## Design principles

1. **Default deny.** Every tool call starts denied; a JSON policy must explicitly
   allow it. Unknown tools are denied automatically.
2. **Data vs. instructions.** Tool *results* are untrusted data, never
   instructions. The detector tags suspicious content `<untrusted-data>` and the
   guarded system prompt tells the model to treat it accordingly.
3. **Defense in depth.** Four layers (detector → policy → sandbox → audit) each
   independently capable of stopping an attack; they fail independently.
4. **Evidence over claims.** Every decision lands in a hash-chained audit log
   verifiable via `/api/audit/verify`. Benchmark numbers are measured, not asserted.

## Components

```
┌─────────────────────────────────────────────────────────────┐
│ Agent loop  (airlock/agent.py)                               │
│  - builds tool-calling loop around an OpenAI-compatible LLM │
│  - GUARD=on wraps 3 hook points; GUARD=off = raw baseline   │
└──────────────┬──────────────────────────────────────────────┘
               │ ① check_tool_call(name, args)
               ▼
┌─────────────────────────────────────────────────────────────┐
│ Policy engine  (airlock/guard/policies.py)                  │
│  - rules from policies/email-agent.json (default-deny)      │
│  - send_email: internal domains only                        │
│  - read_file: data/files/* allowed, data/secrets/* denied  │
│  - browse_web: local pages only (normalized like the tool)  │
│  - run_code: allowed only via sandbox                       │
└──────────────┬──────────────────────────────────────────────┘
               │ ② tool executes (airlock/tools.py → world.py)
               ▼
┌─────────────────────────────────────────────────────────────┐
│ Injection detector  (airlock/guard/detector.py)              │
│  - scans tool RESULTS (③ check_tool_result)                 │
│  - patterns: fake system directives, concealment ("ignore   │
│    previous instructions"), guard-disable orders,            │
│    credential shapes, exfiltration shapes                   │
│  - hit → sanitize: wrap in <untrusted-data>, warn agent     │
└──────────────┬──────────────────────────────────────────────┘
               │ ④ check_output: scan drafts/final answers
               ▼
┌─────────────────────────────────────────────────────────────┐
│ Sandbox  (airlock/guard/sandbox.py)                         │
│  - run_code → fresh temp dir, timeout, output cap,          │
│    blocked-import screen (socket, subprocess, os.system…)   │
│  - demo-grade: process isolation, NOT a container boundary  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Audit  (airlock/guard/audit.py)                              │
│  - every decision → JSONL: ts, tool, args_hash, decision,   │
│    reason, prev_hash → sha256 chain                         │
│  - GET /api/audit/verify → {"ok": true, "records": N}       │
└─────────────────────────────────────────────────────────────┘
```

## Data flow of one guarded run

`demo_attack.py` → `run_agent(guard=Guard())` → for each LLM tool call:
`check_tool_call` → policy allow/deny → execute → `check_tool_result` →
sanitize if injected → back to LLM → before final output, `check_output`
scans for leaked secrets. All four steps append to the audit chain.

## Policy file

`policies/email-agent.json` — the whole firewall posture in one editable file:

```json
{
  "tools": {
    "send_email": { "allow_domains": ["company.com"], "deny_external": true },
    "read_file":  { "allow_paths": ["data/files/*"], "deny_paths": ["data/secrets/*"] },
    "run_code":   { "require_sandbox": true }
  },
  "default_action": "deny"
}
```

## What's designed but not built

- **Layer-B LLM judge** — a second, model-based detector behind the heuristic
  one (planned two-layer detection; the submission does not claim it exists).
- **MCP tool gateway** — proxying remote Model Context Protocol servers
  (the dashboard's Integrations page marks it "planned").
- **Human-approval workflow** for critical actions (policy flag exists in UI draft).
