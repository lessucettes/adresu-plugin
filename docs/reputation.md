# Reputation policy

Use a local follow graph to decide which authors can publish to your relay. The plugin collects signed follow lists from your chosen relays, computes TrustRank from your seed authors, and checks events against the resulting snapshot. No external reputation service or API key is needed.

Reputation is **disabled by default**. It supplements bans, rate limits, and other filters; a high score does not bypass them.

## Get started

Add these sections to your plugin configuration, replacing the seed and relay placeholders with your own choices:

```toml
[reputation]
seeds = ["<64-character hex public key>"]
relays = ["wss://relay.example.com"]
refresh_interval = "1h"
max_age = "72h"
max_depth = 2
min_coverage = 0.8

[filters.reputation]
enabled = true
mode = "observe"
min_trustrank = 0.0
```

Seeds should be authors whose follows you trust. Supply at least one seed and one relay, with no more than eight relay URLs. Configured relays must use `ws://` or `wss://`, include a host, and contain no credentials or URL fragment. Use final relay URLs: redirects are not followed.

Start in `observe` mode. Look for `Local reputation snapshot updated` or `Restored local reputation snapshot` in the plugin logs, then review `Reputation observation` records before enabling enforcement. These messages use the `info` log level.

For general plugin setup, see the [README](../README.md). The [configuration example](../config.toml.example) lists all collector and filter options. To validate configuration, use `-validate` with a disposable database path, not the database of a running relay.

## Choose an admission policy

| Mode | Behaviour |
| --- | --- |
| `observe` | Logs authors who would be rejected, without rejecting their events. Other filters still enforce their policies. |
| `enforce` | Rejects authors absent from a usable graph or below `min_trustrank`, with a client-facing `restricted:` reason. |

Both modes check every non-ephemeral event. Ephemeral kinds (`20000 <= kind < 30000`) bypass reputation but remain subject to other filters. The global `-dry-run` flag previews all plugin policies; `observe` previews only reputation.

### Set a TrustRank threshold

TrustRank distributes trust from the seeds along outgoing follow links. Scores are normalized values in `[0,1]`, not percentages or probabilities that an author is honest. A known author passes when its score is **greater than or equal to** `min_trustrank`.

- **Zero threshold:** requires only membership in the collected graph. It is not Sybil-resistant: a reachable author whose list is fetched can introduce many new keys.
- **Positive threshold:** also requires a minimum share of trust. Choose it from observations of your own graph; there is no universally safe value, and thresholds are not portable between graphs.

Following a seed does not add an account to the graph. Collection follows links outward from the seeds, not back toward their followers.

Set your chosen `min_trustrank` while still in `observe` mode and review the results. Diagnostics include `known`, `trustrank`, and `min_trustrank`. When the decisions match your relay's policy, change `mode` to `"enforce"`.

## Collect the graph

Collection runs in the background. Event processing reads the local snapshot and never waits for a relay request. Only verified kind-3 follow lists are used; older lists do not replace newer ones.

`max_depth` controls how many levels of follow lists are fetched, not the distance of every author retained in the graph:

- `1` fetches the seeds' lists and includes the authors they follow as boundary nodes.
- `2` also fetches those authors' lists and includes their follows.
- Values up to `4` extend the same traversal.

The main collector settings and their defaults are:

| Setting under `[reputation]` | Default | Purpose |
| --- | --- | --- |
| `refresh_interval` | `"1h"` | Refresh cadence; must be positive. |
| `max_age` | `"72h"` | Maximum age of usable data; must be at least `refresh_interval`. |
| `fetch_timeout` | `"10s"` | Timeout for a relay request. |
| `min_coverage` | `0.8` | Required share of requested authors with usable follow lists, in `(0,1]`. Verified empty lists count; missing lists do not. |
| `max_depth` | `2` | Number of levels fetched, from `1` to `4`. |
| `max_nodes` | `50000` | Maximum graph authors. |
| `max_edges` | `1000000` | Maximum follow links. |
| `max_follows` | `5000` | Per-list `p`-tag limit; oversized lists are rejected, not truncated. |
| `batch_size` | `64` | Authors queried per batch. Reduce it if large lists exceed response budgets. |

These limits bound each collection, not the global Nostr network. A refresh that exceeds graph limits, times out, or cannot reach the required coverage does not replace the last usable snapshot.

### Optional relay discovery

If your fixed relays lack some authors' follow lists, enable the NIP-65 outbox fallback. Add these keys to the existing `[reputation]` table:

```toml
discover_relays = true
discovery_relays = ["wss://purplepag.es", "wss://indexer.coracle.social"]
```

The collector queries fixed relays first. For missing authors, it asks the configured discovery relays for signed relay-list metadata, then queries the authors' write relays. Discovery requires one to eight explicit bootstrap URLs and is disabled by default.

Discovered endpoints must use `wss://` and resolve to public addresses. Private and reserved destinations, redirects, and environment proxies are blocked for discovered endpoints. This means discovered traffic connects directly, even when `HTTP_PROXY` or `HTTPS_PROXY` is set; do not treat those variables as a privacy boundary.

The collector supports NIP-42 authentication with a separate anonymous key per connection. It does not use your operator key and cannot satisfy paid or key-specific access restrictions.

## Availability and reload

**Reputation fails open when no usable snapshot exists**, including initial collection and expiry after prolonged relay failures. Other filters continue to apply. Do not use reputation as your only access-control mechanism.

Snapshots and follow lists persist in the plugin's Badger database. A matching, unexpired snapshot can be restored after restart. Failed refreshes retain the previous usable snapshot until it expires. Expiry is bounded by the oldest follow-list receipt plus `max_age`; recalculating cached data does not renew its age.

Changes to `mode` or `min_trustrank` apply through hot reload without rebuilding the graph. Changing seeds or collector settings restarts collection; the previous graph is not used under a different configuration. Checks fail open until a matching usable snapshot is available. Changing `database.path` requires a plugin restart.

Graph limits do not cap total disk usage: cached follow lists for authors that leave the graph are not automatically pruned. Monitor the database directory as part of relay maintenance.

## Logging and bans

Reputation diagnostics go to stderr as `Reputation observation` or `Event rejected by reputation policy`, separately from ordinary `Event rejected by filter` records. They have no `remote_ip` field: relaying an unknown author's event is not evidence of IP abuse.

Keep these records out of Fail2Ban and other log-driven IP bans. If you use broad custom rules, explicitly exclude `ReputationFilter`. The plugin automatically excludes reputation rejections from autoban strikes.
