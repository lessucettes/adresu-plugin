package strfry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakeStrfry installs a fake executable that records its arguments and
// returns successfully.
func writeFakeStrfry(t *testing.T) (executable, argsFile string) {
	t.Helper()

	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args.txt")
	executable = filepath.Join(dir, "strfry")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + argsFile + "'\n"
	if err := os.WriteFile(executable, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake strfry: %v", err)
	}
	return executable, argsFile
}

func TestDeleteEventsByAuthorBuildsExpectedFilter(t *testing.T) {
	executable, argsFile := writeFakeStrfry(t)
	client := NewClient(executable, "/etc/strfry.conf")

	author := strings.Repeat("ab", 32)
	if err := client.DeleteEventsByAuthor(author); err != nil {
		t.Fatalf("DeleteEventsByAuthor: %v", err)
	}

	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read recorded args: %v", err)
	}
	args := strings.Split(strings.TrimSpace(string(raw)), "\n")
	wantFilterArg := `--filter={"authors":["` + author + `"]}`
	if len(args) != 3 {
		t.Fatalf("args = %q, want 3 arguments", args)
	}
	if args[0] != "--config=/etc/strfry.conf" || args[1] != "delete" || args[2] != wantFilterArg {
		t.Fatalf("args = %q, want filter argument %q", args, wantFilterArg)
	}
}

func TestDeleteEventsByAuthorRejectsFilterInjection(t *testing.T) {
	executable, argsFile := writeFakeStrfry(t)
	client := NewClient(executable, "/etc/strfry.conf")

	// Without validation this rewrites the filter JSON, for example to delete
	// events belonging to a different author.
	author := `x"],"authors":["` + strings.Repeat("cd", 32) + ``
	if err := client.DeleteEventsByAuthor(author); err == nil {
		t.Fatal("DeleteEventsByAuthor accepted a malformed author and passed it to strfry")
	}

	if _, err := os.Stat(argsFile); err == nil {
		raw, _ := os.ReadFile(argsFile)
		t.Fatalf("strfry was executed with untrusted author: %q", raw)
	}
}

func TestDeleteEventsByAuthorRejectsEmptyAuthor(t *testing.T) {
	executable, argsFile := writeFakeStrfry(t)
	client := NewClient(executable, "/etc/strfry.conf")

	if err := client.DeleteEventsByAuthor(""); err == nil {
		t.Fatal("DeleteEventsByAuthor accepted an empty author")
	}
	if _, err := os.Stat(argsFile); err == nil {
		t.Fatal("strfry was executed for an empty author")
	}
}

func TestBoundedBufferTruncates(t *testing.T) {
	buffer := &boundedBuffer{limit: 4}

	n, err := buffer.Write([]byte("abcdef"))
	if err != nil || n != 6 {
		t.Fatalf("Write = %d, %v; want 6, nil", n, err)
	}
	if got := buffer.String(); got != "abcd" {
		t.Fatalf("buffer = %q, want %q", got, "abcd")
	}

	if _, err := buffer.Write([]byte("z")); err != nil {
		t.Fatalf("Write after truncation: %v", err)
	}
	if got := buffer.String(); got != "abcd" {
		t.Fatalf("buffer grew past its limit: %q", got)
	}
}

func TestDeleteEventsByAuthorBoundsSubprocessErrors(t *testing.T) {
	executable, _ := writeFakeStrfry(t)
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf '%090000d' 0 >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := NewClient(executable, "/unused.conf").DeleteEventsByAuthor(strings.Repeat("ab", 32))
	if err == nil {
		t.Fatal("subprocess failure was hidden")
	}
	if got := strings.Count(err.Error(), "0"); got != 8<<10 {
		t.Fatalf("captured %d bytes of stderr, want exactly 8 KiB", got)
	}
}
