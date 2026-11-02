# Adresu Plugin for strfry

A policy plugin for the [strfry](https://github.com/hoytech/strfry) Nostr relay (though it can be used with any other relay after small adjustments).

This plugin orchestrates [Adresu Kit](pkg/adresu-kit/README.md), a reusable in-process filter library, and adds persistent moderation through Badger and the `strfry` command-line interface. Kit filters can maintain local rate limits and caches, but do not depend on this plugin, its database, or strfry.

---

## 🛡️ Core Components

* **Filter Pipeline**: Executes a sequence of filters from `adresu-kit` and this plugin.
* **Stateful Moderation**: Provides filters that depend on an external state (a BadgerDB database).
    * **Banned Author Checks**: Rejects events from authors in a persistent ban list.
    * **Moderator Actions**: Allows a moderator to ban/unban users via Nostr reactions. Banning triggers a call to `strfry delete` to purge the user's events. Applied reactions are recorded atomically with the ban/unban in the plugin database; replaying the same reaction does not repeat the action, including after reload or restart.
    * **Autoban**: Automatically bans users based on a configurable number of "strikes" (rejected events).
* **Hot-Reload**: The `config.toml` can be reloaded on the fly without restarting the plugin.

---

## 🚀 Installation

Requires Go 1.25.1 or newer.

```bash
# Clone the repository
git clone https://github.com/lessucettes/adresu-plugin.git
cd adresu-plugin

# Download dependencies (go build also fetches them automatically)
go mod download

# Build the binary
go build ./cmd/adresu-plugin
```

-----

## ✨ Usage

The plugin is executed by `strfry` and communicates over `stdin`/`stdout`.

```
Usage of adresu-plugin:
  -config string
        Path to the configuration file. (default "./config.toml")
  -dry-run
        Log what would be rejected without actually rejecting it.
  -use-defaults
        Run with internal defaults if the config file is missing.
  -validate
        Validate the configuration file and exit.
  -version
        Show plugin version and exit.
```

**Example `strfry.conf` entry:**

```
writePolicy {
  plugin = "/path/to/adresu-plugin -config /etc/adresu/config.toml"
}
```

-----

## ⚙️ Configuration

All behavior is controlled via `config.toml`. See `config.toml.example` for a full list of options. The configuration allows you to chain any filters from `adresu-kit` and enable the stateful moderation policies of this plugin.

Durations use Go duration syntax (`30m`, `24h`, `720h`). There is no day unit: write `168h` instead of `7d`.

Keys are scoped to their table. Kind allow/deny lists belong under `[filters.policy]`, and the global freshness limits are `[filters.freshness] default_max_past`/`default_max_future`; `max_past`/`max_future` are only valid inside a `[[filters.freshness.rule]]`. Unrecognized or misplaced keys are configuration errors: startup and `-validate` fail with a list of these keys. On reload, the error is logged and the previous working configuration remains active. No legacy aliases or automatic key migration are supported.

For client publications, `strfry` applies its own `events.rejectEventsOlderThanSeconds` and `events.rejectEventsNewerThanSeconds` before invoking the plugin, so plugin freshness limits can only tighten those bounds; a larger plugin limit has no effect.

The built-in defaults enable moderation reactions, so `policy.moderator_pubkey` is required unless both `policy.ban_emoji` and `policy.unban_emoji` are cleared. When the configuration file is missing, `-use-defaults` starts with all filters and moderation disabled.

### Reputation filter

The optional `ReputationFilter` checks event authors against a follow-graph ranking computed locally from operator-configured seeds and relays. It is disabled by default and does not call an external reputation API. Collection runs in the background; the event path only reads the latest in-memory snapshot and never waits for a relay.

- All non-ephemeral events are checked. NIP-01 ephemeral kinds (`20000 <= kind < 30000`) bypass reputation.
- `mode = "observe"` is the default: would-reject assessments are recorded for logging, the event is allowed, and the rest of the pipeline still runs. `mode = "enforce"` rejects with a `restricted: ...` reason.
- A missing, stale, or below-coverage snapshot fails open.
- Graph settings live under `[reputation]`; policy settings live under `[filters.reputation]`. Seeds are 64-character hex public keys, and relays must be explicit `ws://` or `wss://` URLs with a host, no credentials, and no fragment. At most eight relays are accepted.
- `PageRank` and `TrustRank` are independent raw scores, not percentages. Both configured minima must pass. Zero minima only prove membership in a bounded graph and are not Sybil-resistant; no threshold is recommended by default.
- There is no paid bypass, no trusted-author bypass, and no default allowlist.
- Reputation observe mode is separate from the global `-dry-run` flag. `-dry-run` suppresses all rejections; observe mode affects only this filter.
- Reputation diagnostics use separate messages without a remote IP so they do not feed the ordinary Fail2Ban rejection stream. Broader custom ban rules must also exclude `ReputationFilter`. Autoban automatically excludes this filter from strike counting.

See [docs/reputation.md](docs/reputation.md) for collection boundaries, BFS depth semantics, persistence and hot reload, failure modes, and the full configuration reference.

### Hot reload

The file passed to `-config` is watched while the plugin runs. After an edit, the configuration is re-read, validated, and swapped in without a restart; if loading or validation fails, the error is logged and the previous configuration stays active. Both relative and absolute `-config` paths are supported. For a symlinked configuration file, the watcher follows target edits and replacement of the configured link.

Two process-wide settings are applied only at startup and require a restart: `database.path` (the database handle is opened once and reused by reloaded pipelines) and `log.level` (the logger is created once). Reload does apply `log.rejection_levels`, filter settings, and moderation settings.

### Validation

`-validate` is not a read-only syntax check. It opens (and may create) the configured Badger database and builds the full filter pipeline, including the language-detection models. Point it at a disposable database path rather than the one used by a running relay.

-----

## Development and package boundaries

- `cmd/adresu-plugin`: CLI, filter construction, reload lifecycle and stdin/stdout protocol. Platform-specific stdin files keep inherited-pipe cancellation portable.
- `internal/config`: plugin TOML loading, defaults, validation and file watching.
- `internal/policy`: plugin pipeline, bans, moderation and autoban.
- `internal/reputation`: relay collection, discovery safety, authentication and background snapshot management.
- `internal/store`: Badger transactions and persistence formats; snapshot loading and saving remain separate operations.
- `internal/strfry`: subprocess adapter for event deletion.
- `pkg/adresu-kit`: public, reusable `cache`, `config`, `nip`, `policy` and `reputation` packages. These must not import `internal/` or `cmd/`; see the [library guide](pkg/adresu-kit/README.md).

Run from the repository root:

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/adresu-plugin
```

Keep files organized by responsibility, not by the change that introduced them. Small regression checks belong beside the component's existing tests; separate files are useful for distinct security, lifecycle, platform or persistence boundaries. Removing an unused private helper does not justify removing a public kit API merely because the plugin does not call it.

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
