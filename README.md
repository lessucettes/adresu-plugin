# Adresu Plugin

Event filtering and moderation for the [strfry](https://github.com/hoytech/strfry) Nostr relay. Define what your relay accepts, control spam and flooding, and manage persistent author bans from a single TOML configuration.

## Features

- **Event policies** — filter by kind, age, size, tags, keywords, regular expressions, and language.
- **Spam protection** — rate limits by IP and public key, new-key flood protection, repost-abuse detection, and ephemeral-chat controls with proof-of-work support.
- **Persistent moderation** — ban and unban authors through moderator reactions, delete a banned author's stored events via strfry, and automatically ban repeat offenders.
- **Local reputation** — optional TrustRank filtering based on a follow graph collected from your chosen seeds and relays, without an external reputation API.
- **Hot reload** — update filters and moderation settings without restarting the plugin; invalid edits leave the working configuration in place.

## Build

Requires Go 1.25.1 or newer.

```bash
git clone https://github.com/lessucettes/adresu-plugin.git
cd adresu-plugin
go build ./cmd/adresu-plugin
```

The binary is written to `./adresu-plugin`. Go downloads dependencies automatically.

## Connect to strfry

Create a `config.toml`. This starter configuration limits event size and publication rate, with moderator reactions disabled:

```toml
[database]
path = "/var/lib/adresu/plugin-db"

[policy]
ban_emoji = ""
unban_emoji = ""

[filters.size]
default_max_size_bytes = 16384

[filters.rate_limiter]
enabled = true
by = "both"
default_rate = 0.5
default_burst = 5
```

Place the configuration at `/etc/adresu/config.toml` and make the database directory writable by the user running strfry. Add the plugin to `strfry.conf`, replacing the binary path with its absolute location:

```text
writePolicy {
  plugin = "/path/to/adresu-plugin -config /etc/adresu/config.toml"
}
```

strfry runs the plugin and exchanges newline-delimited JSON over stdin/stdout. Plugin diagnostics go to stderr.

## Configure your relay

See [config.toml.example](config.toml.example) for the available filters, per-kind rules, moderation settings, and logging options. When using the example, uncomment both the settings and their table headers. Unknown or misplaced keys are rejected. Durations use Go syntax such as `30m`, `24h`, and `168h`.

**Moderation:** set `policy.moderator_pubkey` to the moderator's 64-character hex public key and choose `ban_emoji` and `unban_emoji`. The defaults are 🔨 and 🔓; clear both to disable reactions. Configure `strfry.executable_path` and `strfry.config_path` for event deletion. Autoban is configured separately under `[filters.autoban]`.

**Reputation:** disabled by default. Configure seeds and relays, then start in `observe` mode to assess decisions before enforcing a TrustRank threshold. Collection runs in the background; event checks use a local snapshot. Missing, stale, or insufficiently covered snapshots fail open, and ephemeral events bypass this filter. See the [reputation guide](docs/reputation.md) for setup and limitations.

### Operational notes

- **Preview policies:** add `-dry-run` to log policy rejections without enforcing them or applying moderation actions. Operational errors still reject events.
- **Validate safely:** `-validate -config /path/to/config.toml` opens the configured database and constructs the filters; it is not a read-only syntax check. Use a configuration pointing to a disposable database, not a running relay's database.
- **Reload:** configuration edits apply automatically. Changing `database.path` or `log.level` requires a restart.
- **Freshness:** strfry's own event-age limits run before the plugin; plugin settings cannot relax them.

Run `./adresu-plugin -help` for all command-line options.

## Adresu Kit

The plugin's in-process filters are also available as [Adresu Kit](pkg/adresu-kit/README.md), a reusable Go library for other Nostr applications.

## License

MIT
