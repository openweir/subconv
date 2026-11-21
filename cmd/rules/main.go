// Command rules builds the rules branch of github.com/openweir/subconv: the routing template and
// the rule sets it loads, mirrored from the layout and sources config.yaml names, with a
// manifest of every file. The rules workflow runs it daily; docs/rules.md describes the branch.
//
//	rules -out DIR (-mihomo BIN | -text) [-config FILE] [-prev MANIFEST] [-changed FILE]
//
// It downloads the layout and every rule set, refuses what does not look like one, splits
// classical rule sets into domain, IP and classical parts, compiles domain and IP parts to .mrs
// with mihomo's convert-ruleset, and writes the template, the rule sets, the licenses, NOTICE.md and
// manifest.json into DIR, which must be empty. With -prev, the previous manifest, it keeps the
// dates of unchanged files, refuses rule sets that shrank sharply, and writes to -changed the
// paths that changed (none if nothing did).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/openweir/subconv/rules"
)

func main() {
	configPath := flag.String("config", "cmd/rules/config.yaml", "the sources, licenses and template")
	out := flag.String("out", "", "the empty `directory` to write the branch into")
	mihomo := flag.String("mihomo", "", "the mihomo `binary` that compiles .mrs rule sets")
	textOnly := flag.Bool("text", false, "write text rule sets only, without mihomo")
	prev := flag.String("prev", "", "the previous `manifest`, if any")
	changed := flag.String("changed", "", "the `file` to list changed paths in")
	flag.Parse()
	if *out == "" || flag.NArg() != 0 || (*mihomo == "") == !*textOnly {
		flag.Usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, *configPath, *out, *mihomo, *prev, *changed); err != nil {
		fmt.Fprintln(os.Stderr, "rules:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath, out, mihomo, prevPath, changedPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	b := &builder{
		cfg:   cfg,
		fetch: &fetcher{http: &http.Client{}, maxSize: cfg.MaxSize, token: os.Getenv("GITHUB_TOKEN"), retries: 3, backoff: 2 * time.Second},
		out:   out,
		now:   time.Now().UTC(),
		log:   os.Stderr,
	}
	if mihomo != "" {
		bin, err := filepath.Abs(mihomo)
		if err != nil {
			return err
		}
		b.convert = mihomoConverter(bin)
	}
	if prevPath != "" {
		data, err := os.ReadFile(prevPath)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return err
		default:
			if b.prev, err = rules.ParseManifest(data); err != nil {
				return fmt.Errorf("previous manifest: %w", err)
			}
		}
	}
	if b.out, err = filepath.Abs(out); err != nil {
		return err
	}
	paths, err := b.build(ctx)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "no file changed")
	} else {
		fmt.Fprintf(os.Stderr, "%d files changed\n", len(paths)-1)
	}
	if changedPath != "" {
		text := strings.Join(paths, "\n")
		if text != "" {
			text += "\n"
		}
		return os.WriteFile(changedPath, []byte(text), 0o644)
	}
	return nil
}

// mihomoConverter compiles rule sets with mihomo's convert-ruleset.
func mihomoConverter(bin string) converter {
	return func(ctx context.Context, behavior, src, dst string) error {
		output, err := exec.CommandContext(ctx, bin, "convert-ruleset", behavior, "text", src, dst).CombinedOutput()
		if err != nil {
			return fmt.Errorf("mihomo convert-ruleset %s: %v: %s", filepath.Base(src), err, tail(output))
		}
		if fi, err := os.Stat(dst); err != nil || fi.Size() == 0 {
			return fmt.Errorf("mihomo convert-ruleset %s wrote nothing", filepath.Base(src))
		}
		return nil
	}
}

func tail(output []byte) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	return strings.Join(lines[max(0, len(lines)-5):], " | ")
}
