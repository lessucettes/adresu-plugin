# Adresu Kit

Reusable in-process Nostr filtering and follow-graph ranking. The kit does not import the plugin's `internal/` or `cmd/` packages and requires neither strfry nor Badger, a configuration file, or a running relay.

## Packages

Import individual Go packages, not `pkg/adresu-kit` itself:

| Package | Responsibility |
| --- | --- |
| `cache` | Concurrency-safe LRU with lazy expiration and no background workers |
| `config` | Filter settings, constructible directly in Go; TOML tags do not require a TOML loader |
| `nip` | NIP-13 proof of work, NIP-26 delegation, canonical IDs and signature helpers |
| `policy` | Composable filters implementing `Filter.Match` |
| `reputation` | Verified follow/relay-list parsing, graph construction, PageRank and TrustRank, reader and snapshot types |

The kit is part of the root module `github.com/lessucettes/adresu-plugin`, not a nested module with an independent version. Pin a root-module revision that contains the kit; older plugin releases may predate it. Existing import paths remain usable from another module. For local development, a consumer can use:

```bash
go mod edit -require=github.com/lessucettes/adresu-plugin@v0.0.0
go mod edit -replace=github.com/lessucettes/adresu-plugin=/path/to/adresu-plugin
go mod tidy
```

A local `replace` is for development only; consumers of a published application need an available root-module version or commit. Go requirements are inherited from the root `go.mod`. Importing `policy` also compiles its language-detection dependency, even if only another filter is used; model preloading happens only when `GetGlobalDetector` is called.

## Minimal application

This example applies a kind policy to an already admitted event. It is not a relay or a signature-admission implementation.

```go
package main

import (
    "context"
    "fmt"
    "log"

    "fiatjaf.com/nostr"
    "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
    "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"
)

func main() {
    filter, err := policy.NewKindFilter(&config.KindFilterConfig{
        AllowedKinds: []int{1},
    })
    if err != nil {
        log.Fatal(err)
    }
    // In a relay, decode and verify the actual incoming event first.
    event := &nostr.Event{Kind: nostr.KindTextNote}
    result, err := filter.Match(context.Background(), event, nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(result.Allowed) // true
}
```

## Filter contract

- Pass a non-nil configuration pointer, context and event. Some constructors tolerate nil settings, but this is not a uniform disabled-filter convention. Enable flags and zero values are filter-specific; the plugin's defaults and validation are not automatically applied to standalone callers.
- Keep configurations, including referenced maps and slices, unchanged after construction. Several filters retain them rather than copying them. `NewRepostAbuseFilter` clamps `MaxRatio` into `[0,1]` in the supplied configuration during construction; do not share it concurrently while constructing a filter.
- `Allowed == false` with a nil error is an ordinary policy rejection. A non-nil error is an operational failure; the application decides how to handle it. `Filter`, `Reason` and `Duration` support application-owned diagnostics; duration measures time since the call's result helper was created.
- Each application owns ordering, early rejection, logging, metrics and the wire response. Kit filter names remain the existing names used by the plugin's configuration. The kit does not provide the plugin pipeline, bans, moderator actions or autoban.
- Stateful filter instances retain local rate limits and caches. Reuse an instance to preserve those limits; rebuilding it resets its local state. Filters synchronize their local state, but callers must not mutate events/configurations during evaluation or share mutable metadata maps across simultaneous calls.
- Filter matches do not provide general event admission. Validate wire fields, the event ID and signature before applying policy. For events signed with non-lowercase wire pubkeys, use `nip.WithWirePubKey` with the original spelling and the same event pointer before `nip.CanonicalEventID` and `nip.CheckEventSignature`. Delegation helpers validate delegation, not the event's own signature.
- Filters do not start collection workers or launch subprocesses. `LanguageFilter` constructor warnings use the process default `slog` logger; callers own its configuration. Supply a Lingua detector when language filtering is enabled, optionally using `policy.GetGlobalDetector` to share preloaded models.

### Metadata

A nil metadata map is valid. Otherwise, create a fresh map for each event and pass it through that event's filter sequence:

| Key | Value | Direction |
| --- | --- | --- |
| `remote_ip` | `string` | Application supplies it for IP rate/emergency limits; absent or empty skips the IP bucket |
| `language` | `string` | Language filter records a detected/accepted language when applicable |
| `policy.ReputationObservationKey` | `reputation.Assessment` | Observe-mode would-reject assessment; the application logs it and may continue other filters |
| `policy.ReputationDiagnosticKey` | `policy.ReputationDiagnostic` | Numeric details for rejected/would-reject assessments; keep administrative details out of client-facing text |

`dry_run` is a plugin policy concern, not a kit-wide bypass. An application that implements dry-run must translate decisions itself and control its own side effects.

## Reputation without the plugin

`policy.NewReputationFilter` accepts a `reputation.Reader`. Implement its nonblocking `Lookup(nostr.PubKey) reputation.Assessment` method using your own in-memory snapshot. An enabled filter requires a reader; a disabled one does not. `Ready == false` fails open, while `Known == false` in a ready snapshot is a would-reject/reject assessment depending on the configured mode. The default mode is `observe`. Both score thresholds must pass in enforce mode; NIP-01 ephemeral kinds bypass reputation.

To build scores yourself, parse signed kind-3 events with `reputation.ParseFollowList`, then pass verified lists and explicit seeds to `reputation.Calculate` with `reputation.Options`. The application owns network access, input node/edge limits, refresh scheduling, persistence, coverage and expiry; `Calculate` does not collect data or publish snapshots. Published score maps must be treated as immutable. `ParseRelayList` verifies and extracts NIP-65 write URLs, but URL parsing is not SSRF protection: apply your own DNS/address/redirect policy before connecting to untrusted endpoints.

The plugin's implementation and operator settings are described in [the reputation guide](../../docs/reputation.md); they are not required to use the kit.

## Verification

From the root checkout:

```bash
go test ./pkg/adresu-kit/...
go test -race ./pkg/adresu-kit/...
go vet ./pkg/adresu-kit/...
```
