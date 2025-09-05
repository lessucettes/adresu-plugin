
# Adresu Plugin for Strfry

[![Go Version](https://img.shields.io/badge/go-1.25-blue.svg)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![My NIP-05](https://img.shields.io/badge/NIP--05-__@dukenukemmustdie.com-8E44AD?logo=nostr&logoColor=white)](https://dukenukemmustdie.com)

**Adresu Plugin** is a powerful, high-performance plugin for the [strfry](https://github.com/hoytech/strfry) Nostr relay (though it can be used with any other relay after small adjustments), written in Go. It extends a standard relay with a sophisticated, rule-based filtering and moderation engine.

With Adresu Plugin, relay operators can enforce fine-grained policies for event acceptance, protect their servers from spam and abuse, and cultivate a higher-quality, safer environment for their users. The plugin is designed for flexibility, allowing you to enable and configure only the features you need.

-----

## ✨ Key Features

  * **Advanced Event Filtering**: A multi-layered system to inspect and reject events based on their age, size, tags, content, and even language.
  * **Automated Moderation**: An automatic banning system that issues "strikes" to users for policy violations, leading to temporary bans.
  * **Anti-Spam & Rate Limiting**: Powerful rate limiters to prevent event flooding, with support for limits by IP, pubkey, or both. Includes special protections for ephemeral (Bitchat) chats.
  * **Flexible Configuration**: All features are managed through a single, well-documented `config.toml` file, allowing you to tailor the relay's behavior precisely.

-----

## 🚀 Getting Started

### Installation

To install the plugin, clone the repository and build the binary from the source.

```bash
# Clone the repository
git clone https://github.com/your-username/adresu-plugin.git
cd adresu-plugin

# Build the binary
go build
```

### Usage

The plugin is operated via the command line.

```bash
Usage of adresu-plugin:
  -config string
        Path to the configuration file. (default "./config.toml")
  -use-defaults
        Run with internal defaults if the config file is missing.
  -validate
        Validate the configuration file and exit.
  -version
        Show plugin version and exit.
```

**Examples:**

  * **Run with a specific config:**

    ```bash
    ./adresu-plugin -config /etc/adresu/config.toml
    ```

  * **Validate your configuration file:**

    ```bash
    ./adresu-plugin -validate
    ```

-----

## ⚙️ Configuration

Adresu Plugin is configured using a `config.toml` file. A fully-commented template is provided in `config.toml.example`.

1.  **Create your configuration:**

    ```bash
    cp config.toml.example config.toml
    ```

2.  **Edit `config.toml`:** Open the file and customize the settings. Uncomment the sections for the filters you wish to enable and adjust their parameters.

-----

## 🛡️ Filters Overview

Filters are the core of Adresu Plugin. You can enable and combine them to create a robust moderation policy.

### Policy Filters

  * **Kind Filter**: The most basic filter. It allows you to define which event `kinds` are accepted or rejected by the relay using `allowed_kinds` and `denied_kinds` lists.
  * **Freshness Filter**: Rejects events with a `created_at` timestamp that is too old (`max_past`) or too far in the future (`max_future`). This helps prevent replay attacks and clock-skew issues.
  * **Size Filter**: Enforces limits on the total size of an event in bytes. You can set a `default_max_size_bytes` and create specific rules for different event kinds.

### Content & Structure Filters

  * **Tags Filter**: Provides granular control over event tags. You can set the maximum number of tags (`max_tags`), require specific tags to be present (`required_tags`), and limit the count of individual tag types (`max_tag_counts`).
  * **Keywords Filter**: Scans event content for deny-listed words (`words`) or complex patterns using regular expressions (`regexps`). Ideal for blocking common spam, malicious links, or unwanted content.
  * **Language Filter**: Restricts events to a specific list of languages (`allowed_languages`). It's effective for regional relays or communities with a primary language.

### Anti-Spam & Abuse Filters

  * **Rate Limiter**: A powerful tool to prevent spam and flooding. It can limit users by `ip`, `pubkey`, or `both`. You can set a default rate and burst and define stricter rules for specific event kinds.
  * **Ephemeral Chat Filter**: A specialized set of rules for chats. It includes anti-flood delays, limits on capital letters and character repetition, and a hybrid PoW system that requires proof-of-work if a user exceeds the rate limit.
  * **Repost Abuse Filter**: Fights spammy behavior by calculating the ratio of reposts (kinds 6 and 16) to original content from a user. If the `max_ratio` is exceeded, further reposts are rejected.
  * **Autoban Filter**: The automated moderation engine. It issues a "strike" when a user sends an event that is rejected by other filters. If a user accumulates `max_strikes` within the `strike_window`, they are automatically banned for the `ban_duration`. You can specify which filters should not issue strikes via `exclude_filters_from_strikes`.

-----

## 🤝 Contributing

Contributions are welcome\! If you have a suggestion or find a bug, please open an issue or submit a pull request.

-----

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
