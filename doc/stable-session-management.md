# Stable Session Management

This document describes the stable session identity, reliable command delivery,
cleanup and collaboration model added for multi-target drills.

## Problem

The legacy pool distinguishes hooked browsers by IP or browser fingerprint. When
several machines share one egress IP, or fingerprints are near-identical,
instructions can be routed to the wrong target. There is also no receipt beyond
"sent", no timeout/retry, no passive cleanup and no ownership model.

## Opt-in design

Everything is gated by `beef.session_management.enable` (default `false`). When
disabled BeEF behaves exactly as before: no lifecycle sweeper runs, no delivery
state machine intervenes and the legacy session model is preserved.

## Identity

- A session id is 32 random bytes rendered as 64 hex characters
  (`SecureRandom` server-side, `crypto.getRandomValues` client-side). It is an
  opaque token: it encodes no IP, fingerprint or database id, so internal
  structure cannot be inferred from it.
- The id is generated once and is stable for the browser lifetime.
- The browser persists the id in `localStorage` (plus the existing evercookie
  stores), so a control-plane restart does not orphan the browser. On reconnect
  the browser presents its persistent id and is reattached to the original
  session.
- Collisions are effectively impossible but are handled anyway: a colliding id is
  reallocated and an `identifier_reallocated` audit event is recorded.
- Multiple browsers behind one egress IP keep distinct sessions; identity is
  never derived from IP or fingerprint.

### Tab semantics

Configured with `beef.session_management.tab_scope`:

- `browser` (default): all tabs share one session id via `localStorage`. A command
  targets the whole browser, eliminating "sent to tab A while the user is on tab B"
  ambiguity.
- `tab`: each tab gets its own id via `sessionStorage`.

## Command delivery

Instructions still ride the existing XHR-poll response or WebSocket frame; no new
channel or dependency is introduced. A delivery state machine is layered on top:

```
pending --send--> sent --ack--> acked --results--> completed
                  |
                  +--ack timeout--> pending (bounded retries)
                  +--retries exhausted--> failed (session marked lost)
```

- The browser ACKs through the existing `beef.net` transport to the mounted
  `/ack` handler (both XHR and WebSocket envelopes are accepted).
- Execution results continue to flow through the existing command handlers;
  returning results transitions the command to `completed`.
- The reaper requeues unacknowledged instructions up to
  `max_delivery_attempts`. After the final attempt the command fails and its
  session is flagged `stale` (`delivery_lost`), making the unresponsive target
  visible instead of silently dropping the instruction.

## Cleanup and audit separation

- Passive: `SessionManager.sweep_stale` marks sessions silent for longer than
  `session_timeout` as `stale` with reason `passive_timeout`.
- Active: operators close a session through the REST API; it is marked `closed`
  with reason `operator` and the row is retained.
- Lifecycle events live in the `session_events` table, separate from the general
  `logs` table, so loss-rate statistics never count manual closures as losses.

## Ownership and permissions

Each session records an `owner`, an `operators` list and a hierarchical role:

| Role     | Permissions                 |
|----------|-----------------------------|
| readonly | view                        |
| execute  | view, execute instructions  |
| owner    | view, execute, close        |

The owner always resolves to the `owner` role regardless of the default role.
Denied actions are recorded as `permission_denied` events.

## REST endpoints

All endpoints require the existing API token.

- `GET  /api/hooks/report` - session counts, delivery metrics, same-IP groups
- `POST /api/hooks/:session/close` - operator soft close
- `POST /api/hooks/:session/revive` - reattach a reconnecting browser
- `POST /api/hooks/:session/ownership` - set owner/role, attach operators
- `GET  /api/hooks/:session/permissions?operator=` - effective role/permissions
- `GET  /api/hooks/:session/delivery` - per-command delivery state and timestamps

## Configuration

```yaml
beef:
  session_management:
    enable: false
    session_timeout: 300
    reap_interval: 30
    max_delivery_attempts: 3
    ack_timeout: 60
    tab_scope: "browser"
```

No new runtime dependencies are required.

## Acceptance drill record

Reproduce with:

```
bundle exec ruby tools/drill_session_management.rb
```

Scenario: 5 controlled browsers, 3 of them behind one egress IP
(`203.0.113.50`). Each receives one instruction. Four targets ACK and return
results; one target goes dark and exhausts its delivery attempts. The first
target then reconnects to simulate a control-plane restart.

Observed record:

```json
{
  "sessions": {
    "total": 5,
    "active": 4,
    "stale": 1,
    "closed": 0,
    "passive_timeouts": 0,
    "operator_closures": 0,
    "lost_rate": 0.2
  },
  "delivery": {
    "total": 5,
    "by_state": {
      "pending": 0,
      "sent": 0,
      "acked": 0,
      "completed": 4,
      "failed": 1
    },
    "acknowledged": 4,
    "completed": 4,
    "failed": 1,
    "ack_rate": 0.8,
    "success_rate": 0.8
  },
  "same_ip_multi_instance": {
    "203.0.113.50": ["t-alpha", "t-bravo", "t-charlie"],
    "distinct_sessions_behind_shared_ip": 3,
    "cross_talk_detected": false
  },
  "restart_recovery": {
    "session": "t-alpha",
    "restored_to_same_row": true,
    "outcome": "restored"
  }
}
```

Interpretation:

- 5 distinct sessions, 4 active and 1 correctly flagged lost.
- Delivery success rate 80% (4 completed / 5), with the single failure tied to
  the unresponsive target rather than misrouting.
- Three sessions coexist behind one egress IP with no cross-talk.
- The reconnecting browser is restored to its original session row.
