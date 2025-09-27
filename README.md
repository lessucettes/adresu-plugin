
# Adresu Plugin for strfry

[![My NIP-05](https://img.shields.io/badge/NIP--05-__@dukenukemmustdie.com-8E44AD?logo=nostr&logoColor=white)](https://dukenukemmustdie.com)

A policy plugin for the [strfry](https://github.com/hoytech/strfry) Nostr relay (though it can be used with any other relay after small adjustments).

This plugin acts as an orchestration layer for the filter library [Adresu Kit](https://github.com/lessucettes/adresu-kit). It extends the stateless filtering capabilities of the library with stateful moderation tools that require direct integration with a database and the `strfry` command-line interface. With Adresu Plugin, relay operators can enforce fine-grained policies for event acceptance, protect their servers from spam and abuse, and cultivate a higher-quality, safer environment for their users. 

---

## 🛡️ Core Components

* **Filter Pipeline**: Executes a sequence of filters from `adresu-kit` and this plugin.
* **Stateful Moderation**: Provides filters that depend on an external state (a BadgerDB database).
    * **Banned Author Checks**: Rejects events from authors in a persistent ban list.
    * **Moderator Actions**: Allows a moderator to ban/unban users via Nostr reactions. Banning triggers a call to `strfry delete` to purge the user's events.
    * **Autoban**: Automatically bans users based on a configurable number of "strikes" (rejected events).
* **Hot-Reload**: The `config.toml` can be reloaded on the fly without restarting the plugin.

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/lessucettes/adresu-plugin.git
cd adresu-plugin

# Fetch dependencies
go get

# Build the binary
go build
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

-----

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

