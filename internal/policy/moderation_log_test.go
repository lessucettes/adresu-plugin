package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"fiatjaf.com/nostr"
)

func TestModeratorBanLoggedAtWarn(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	moderatorSK, moderator := newKeyPair(t)
	_, target := newKeyPair(t)
	db := newTestStore()
	filter := newModerationFilter(t, moderator, "🔨", "🔓", db, &testStrfry{})
	t.Cleanup(func() { _ = filter.Close() })
	event := signedEvent(t, moderatorSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", target.Hex()}})
	result, err := filter.Match(context.Background(), event, nil)
	if err != nil || !result.Allowed || !db.isBanned(target) {
		t.Fatalf("moderator ban failed: %+v, %v", result, err)
	}
	if err := filter.Close(); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &record); err != nil {
		t.Fatalf("missing ban log at WARN threshold: %v", err)
	}
	if record["level"] != "WARN" || record["msg"] != "Moderator action: banning pubkey" || record["banned_pubkey"] != target.Hex() {
		t.Fatalf("unexpected moderator ban log: %+v", record)
	}
}
