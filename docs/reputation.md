# Reputation policy

The `ReputationFilter` checks event authors against a follow-graph ranking that
the plugin computes locally. It is **disabled by default**. No external
reputation service, API key, or remote score provider is involved.

The filter is policy-only: it reads a prepared snapshot and decides whether an
event may proceed. It never fetches relays, computes ranks, or waits on the
network while handling an event.

## What is checked

- Every non-ephemeral event is in scope, regardless of author or payment
  status. This includes kind 0, 1, 3, 4, 5, 6, 7, addressable events, and all
  other kinds outside the ephemeral range.
- NIP-01 ephemeral events (`20000 <= kind < 30000`) bypass reputation checks.
  They still pass through every other configured filter.
- Disabling the filter means no snapshot lookup and no change to any event.
- There is no free/paid split and no payment-based bypass is implemented.
- There is no built-in trusted-author allowlist or default bypass. Other
  filters, bans, and moderation continue to apply normally.

## Modes

`observe` is the default and the recommended starting point.

| Mode | Behaviour |
| --- | --- |
| `observe` | Never rejects. When a ready snapshot says the author would be rejected, the filter records a `reputation.Assessment` in `meta["reputation_observation"]` (exported as `kitpolicy.ReputationObservationKey`) and allows the event, so the rest of the pipeline still runs. The plugin integration owns logging. |
| `enforce` | Rejects with `Allowed: false` and a reason beginning with `restricted: ` when a ready snapshot says the author is unknown or below the configured minima. |

Observe mode is the filter's own shadow mode, not the global `-dry-run` flag.
`-dry-run` changes all policy rejections to accepts and suppresses rejection
handlers. Reputation observe mode affects only this filter: every other filter
keeps enforcing, and no reputation rejection reaches autoban.

A disabled filter accepts without a reader. An enabled filter requires a
`reputation.Reader`; construction fails otherwise. An empty mode passed to the
kit constructor is treated as `observe` for standalone callers.

## Scores and thresholds

The snapshot exposes two independent raw scores:

- `PageRank`: normalized PageRank mass from the bounded follow graph.
- `TrustRank`: normalized trust mass from the same graph.

They are normalized probability masses, not percentages or probabilities that
an author is honest, and they are not combined into one number. A known author
passes only when **both** individual raw scores are greater than or equal to
their configured minima:

```toml
[filters.reputation]
enabled = true
mode = "enforce"
min_pagerank = 0.0
min_trustrank = 0.0
```

Zero minima are valid. In `enforce`, zero minima mean only that the author is
present in the bounded graph. That is graph-membership policy, **not**
Sybil-resistant reputation. A reachable account whose list is fetched can
introduce many new keys; graph membership alone does not measure trust strength.
Merely following a seed does not add an account to this outward-follow graph.

No universally safe threshold is shipped or recommended. Operators must choose
values based on their own graph, after running observe mode and inspecting the
would-reject assessments. A score that is reasonable for one relay's graph is
not portable to another.

## How the graph is collected

The collector runs in the background inside the plugin process:

- By default it connects only to the relays in `reputation.relays`. The list is an
  explicit allowlist of at most eight URLs. Relay URLs must be `ws://` or
  `wss://` with a host, no credentials/userinfo, and no fragment.
- It speaks WebSocket directly to each relay instead of using a pooled
  subscription client. WebSocket frames are capped at 2 MiB, EOSE is treated as
  the completion signal for a fetch, and HTTP redirects are not followed. At
  most eight relay requests run concurrently in a batch. Each relay batch also
  has a 32 MiB total response budget and a bounded frame count. Configure the
  final relay URLs explicitly. These byte limits are independent of
  `max_follows`: very large lists can hit the byte limit first; reduce batch
  size when large lists exceed the batch budget.
- NIP-42 authentication is supported for configured and discovered relays.
  Every connection generates a separate anonymous key, never an operator key.
  Only a matching positive AUTH acknowledgement unlocks a fresh subscription;
  the old subscription is closed and pre-authentication data is discarded.
  Anonymous AUTH cannot bypass paid or key-specific relay access restrictions.
- It starts from the public keys in `reputation.seeds`, all expressed as
  64-character hex keys.
- It fetches kind-3 follow lists and verifies each event's signature with the
  kit's strict canonical encoding. Only valid events enter the graph. Kind 3 is
  replaceable: the newest valid list by `created_at` is the author's current
  list. Older list events do not overwrite a newer one.
- Traversal is a bounded breadth-first search, not the global Nostr graph.
  `max_depth` is the number of BFS levels **fetched**:
  - depth 1 fetches the seed authors' lists and includes their targets as
    boundary nodes;
  - depth 2 also fetches the lists of authors directly followed by the seeds.
  - deeper levels continue the same pattern.
- `max_nodes`, `max_edges`, `max_follows`, and `batch_size` cap memory, work,
  and per-list fan-out. Every `p` tag counts toward `max_follows`, including
  malformed and repeated tags, before curve validation. Oversized lists are
  rejected, never silently truncated into a different adjacency list. Parsing
  checks cancellation periodically; unrequested authors are discarded before
  expensive event validation.
- When `reputation.discover_relays` is enabled, a bounded targeted NIP-65
  fallback runs only for authors the fixed relays did not return. See below.

Signatures matter because a relay is not trusted to invent follows. Invalid or
malformed kind-3 events are ignored. Replaceable semantics prevent an old,
stale contact list from overwriting a newer one during collection.

## Optional NIP-65 outbox fallback

The fallback is **disabled by default**. When
`reputation.discover_relays = true`, the collector still runs the fixed
`reputation.relays` query first. Only authors missing from that completed pass
are looked up individually:

1. Query `reputation.discovery_relays` for the missing authors' signed kind
   10002 relay-list metadata. These are bootstrap/indexer relays such as
   `wss://purplepag.es` or `wss://indexer.coracle.social`. One to eight
   explicit `ws://` or `wss://` URLs are required; they use the same host,
   credentials, and fragment validation as `reputation.relays`. Static
   operator bootstrap URLs may use loopback (`ws://127.0.0.1:...`) in tests or
   local deployments.
2. Verify each metadata event with the kit's strict canonical signature check.
   At most 32 `r` tags are accepted. Only `wss://` URLs without userinfo or a
   fragment are candidates; `read`-only and unknown markers are excluded. At
   most four write relay URLs are selected per author. Metadata that is
   malformed, wrongly authored, has an invalid signature/ID, or is more than
   five minutes in the future is ignored, so its URLs are never followed.
3. Group missing authors by discovered write relay and query kind-3 lists from
   those relays. One grouped query can serve many authors. A single fetch uses
   at most 64 unique discovered endpoints and at most eight concurrent network
   requests; each request respects `fetch_timeout`, the parent context, and the
   overall refresh deadline. Each group of metadata or outbox queries shares a
   32 MiB response budget across all endpoints, checked before event parsing.
   Write-relay URLs are limited to 2 KiB each before parsing or caching.

Discovered relay URLs face stricter transport checks than the operator's fixed
list. They must be `wss://` with no credentials or fragment. The discovery HTTP
transport has no proxy function (so `HTTP_PROXY`/`HTTPS_PROXY` cannot reroute
it), rejects redirects, and resolves the host inside `DialContext` on every
connection. Both the resolved and actually dialed address must be public:
loopback, private, link-local, unspecified, multicast, reserved, and CGNAT
destinations are blocked. IPv4-mapped addresses are checked as IPv4, so mapping
cannot bypass the guard.
A DNS answer cannot be checked once and then rebound to a different address
at dial time.

Discovery metadata is cached only in worker-owned memory, never in the
database. The cache is capped by `max_nodes` and each entry counts, including
negative entries. The latest signed metadata wins by `created_at`, then the
lower event ID, and fresh metadata is reused for up to one hour. A successful
lookup that finds no metadata marks the author missing for five minutes; it is
not turned into an empty relay list or an empty follow list. Transient
bootstrap failures are retried after five minutes and never cached
indefinitely. A failed refresh keeps previously verified metadata. Completed
per-author NIP-65 results can be merged with fixed-source results, but only
events returned after EOSE are used; a partial pre-EOSE response cannot
establish readiness or refresh a cache age.

## Persistence, lifecycle, and reload

Snapshots live in the plugin's Badger database, alongside bans and moderation
state. The database handle is opened once and shared by the pipeline lifecycle.
Persistence uses the store's existing Badger defaults; this feature does not
introduce an additional power-loss/fsync guarantee. Follow-list cache rows keep
the latest version per discovered author, but authors that leave the graph are
not automatically pruned. Graph limits bound each calculation, not the total
historical cache footprint on disk.

- A successful collection persists a complete snapshot generation. The event
  path reads only the in-memory snapshot published by the runtime.
- An unchanged signed follow list refreshes only a small per-author receipt
  header; its stored adjacency array is not rewritten. Replacement updates the
  list and receipt together in one transaction.
- Hot reload rebuilds filters and swaps the pipeline, but it does not drop the
  Badger handle or the persisted snapshot. Policy-only changes keep the worker
  and its usable snapshot. Changing seeds or other graph settings restarts the
  worker; the old graph is not used under a different configuration. Until a
  matching usable snapshot is available, reputation checks fail open.
- `database.path` still requires a restart, as with the rest of the plugin.
  `refresh_interval` and the collector limits are re-read on reload and apply
  to subsequent background collection.

Only one snapshot is active at a time. A refresh that fails or stays below
`min_coverage` leaves the previous usable snapshot in place until it exceeds
`max_age`. Coverage measures requested authors with verified, sufficiently
recent cached lists; missing lists do not count, but verified empty lists do.
Only sources that complete a batch with EOSE contribute fetched lists to the
cache; if all sources fail, only the existing cache can be used. A
refresh can publish only if coverage and all other bounds pass, and its
`valid_until` is limited by the oldest list's `fetched_at + max_age`: repeatedly
recomputing stale cache data cannot extend the fallback window.

Lists observed within `refresh_interval` are reused without another network
query or receipt write unless approaching expiry within the worker's refresh
budget, including when `max_age` equals `refresh_interval`.
After an interrupted crawl, the next attempt therefore skips successfully
cached fresh authors and can continue to later BFS batches. Missing authors
are still queried, so this is not a guarantee that every large graph can finish
within the deadline. Cached authors still count toward coverage and all graph
limits; no partial graph is published. A complete graph can combine receipts
from several interrupted attempts, always bounded by its oldest receipt.

## Failure modes and max-age fallback

The filter fails open. An event is never rejected because reputation data is
missing, stale, or unusable.

- At startup, before the first successful collection, the snapshot is not
  ready. Every event passes the reputation filter until a ready snapshot
  exists.
- Relay failures, timeouts, invalid events, redirects, and truncated lists can
  leave a partial graph. A snapshot whose coverage is below `min_coverage` is
  not marked ready.
- With discovery enabled, a failed bootstrap indexer or discovered write relay
  leaves that author missing for this pass. It is never counted as an empty
  follow list, and verified metadata from an earlier pass is retained for the
  next attempt. Completed per-author discovery results may still merge with
  completed fixed-relay results.
- A ready snapshot remains usable until it is older than `max_age`. This is the
  fallback window: transient collector failures do not immediately disable
  enforcement.
- Once the newest usable snapshot is older than `max_age`, lookups report not
  ready and the filter fails open again.
- `max_age` must be at least `refresh_interval`. After a successful refresh,
  the worker shortens its next wait when needed to leave a full refresh budget
  before `valid_until`, including when the two configured durations are equal.
  If cached data is already inside that budget, retries wait the smaller of
  five seconds and `refresh_interval` instead of running in a tight loop.
- Failures are logged by the runtime on stderr. They never block or delay the
  event path.
- Each refresh has an overall deadline of the smallest of 15 minutes,
  `refresh_interval`, and `max_age / 2`. A slow source cannot extend one cycle
  indefinitely across hundreds of separately timed batches. Deadline failure
  retains the last usable snapshot; it does not publish the partial graph.
- Stale or now-over-budget cached lists count as missing for `min_coverage`,
  rather than poisoning every future refresh. Database corruption and I/O
  errors remain operational failures, not silently accepted missing data.

## Configuration

```toml
[reputation]
seeds = [
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
]
relays = ["wss://relay.example.com"]
discover_relays = false
discovery_relays = []
refresh_interval = "1h"
max_age = "72h"
fetch_timeout = "10s"
max_depth = 2
max_nodes = 50000
max_edges = 1000000
batch_size = 64
max_follows = 5000
min_coverage = 0.8
damping = 0.85
tolerance = 1e-8
max_iterations = 200

[filters.reputation]
enabled = false
mode = "observe"
min_pagerank = 0.0
min_trustrank = 0.0
```

Defaults:

| Key | Default | Validation |
| --- | --- | --- |
| `reputation.seeds` | unset | required and valid hex when enabled |
| `reputation.relays` | unset | required; at most 8; `ws://`/`wss://` URLs with a host, no credentials or fragment |
| `reputation.discover_relays` | `false` | boolean |
| `reputation.discovery_relays` | unset | when discovery is enabled: at most 8; same URL validation as `relays` |
| `reputation.refresh_interval` | `1h` | positive |
| `reputation.max_age` | `72h` | positive, at least `refresh_interval` |
| `reputation.fetch_timeout` | `10s` | positive |
| `reputation.max_depth` | `2` | 1..4 |
| `reputation.max_nodes` | `50000` | 1..1000000 |
| `reputation.max_edges` | `1000000` | 1..20000000 |
| `reputation.batch_size` | `64` | 1..200 |
| `reputation.max_follows` | `5000` | 1..50000 |
| `reputation.min_coverage` | `0.8` | finite, in (0,1] |
| `reputation.damping` | `0.85` | finite, in (0,1) |
| `reputation.tolerance` | `1e-8` | finite, > 0 |
| `reputation.max_iterations` | `200` | 1..10000 |
| `filters.reputation.enabled` | `false` | boolean |
| `filters.reputation.mode` | `observe` | `observe` or `enforce` |
| `filters.reputation.min_pagerank` | `0.0` | finite, in [0,1] |
| `filters.reputation.min_trustrank` | `0.0` | finite, in [0,1] |

Collector settings are validated only while `filters.reputation.enabled` is
true. A disabled filter needs no seeds or relays and does not start collection.
Existing configurations keep their current behavior because reputation is
disabled by default.

## Standalone kit use

`pkg/adresu-kit/policy` is usable without the plugin:

```go
filter, err := kitpolicy.NewReputationFilter(&kitconfig.ReputationFilterConfig{
    Enabled:      true,
    Mode:         kitconfig.ReputationModeObserve,
    MinPageRank:  0.001,
    MinTrustRank: 0.001,
}, reader)
```

The caller supplies a `reputation.Reader` and owns collection, persistence, and
logging. In observe mode, the filter returns `Allowed: true` and puts a
`reputation.Assessment` under `meta[kitpolicy.ReputationObservationKey]`
(the literal key is `reputation_observation`). It does not create a logger or
write observation logs itself. Autoban integrations should exclude
`kitpolicy.ReputationFilterName` from strike counting so a reputation rejection
cannot itself trigger an author ban. This repository's parent wiring performs
that exclusion.

## Production checklist

1. Leave the filter disabled until the relay list and seeds are settled.
2. Enable it in `observe` mode. Confirm the collector produces a ready
   snapshot and inspect the `Reputation observation` diagnostic records.
3. Choose thresholds from observed data. Remember that zero minima only prove
   graph membership.
4. Keep reputation diagnostics out of log-driven IP bans. The plugin uses
   `Reputation observation` and `Event rejected by reputation policy` messages
   without a `remote_ip` field, separate from ordinary `Event rejected by filter`
   records. If using broader custom ban patterns, explicitly exclude
   `ReputationFilter`: forwarding an unknown author's event is not IP abuse.
5. Verify that autoban excludes `ReputationFilter` from strikes. The parent
   pipeline does this automatically; custom integrations must do the same.
6. Expect fail-open behavior during collection outages. Reputation is an
   additional filter, not a replacement for bans, rate limits, or moderation.

## Non-goals

- It is not a global or network-wide reputation system.
- It is not Sybil-resistant, especially with zero thresholds.
- It does not bypass other filters or moderation for trusted authors.
- It does not implement payments or paid exemptions.
- It does not fetch missing data on the event path.
