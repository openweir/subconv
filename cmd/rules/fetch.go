package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// fetcher downloads upstream files, retrying transient failures, and refuses what cannot be a
// rule file: error pages, binary data, bodies over the size limit.
type fetcher struct {
	http    *http.Client
	maxSize int64
	retries int
	backoff time.Duration
}

func (f *fetcher) get(ctx context.Context, u string, header http.Header) ([]byte, error) {
	data, err := f.download(ctx, u, header)
	if err != nil {
		return nil, err
	}
	if err := checkText(data); err != nil {
		return nil, fmt.Errorf("%s: %w", u, err)
	}
	return data, nil
}

func (f *fetcher) download(ctx context.Context, u string, header http.Header) ([]byte, error) {
	var err error
	for attempt := 0; attempt <= f.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(f.backoff << (attempt - 1)):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		var data []byte
		var retry bool
		data, retry, err = f.once(ctx, u, header)
		if err == nil {
			return data, nil
		}
		if !retry {
			break
		}
	}
	return nil, fmt.Errorf("%s: %w", u, err)
}

func (f *fetcher) once(ctx context.Context, u string, header http.Header) (data []byte, retry bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", "openweir-subconv-rules")
	resp, err := f.http.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("HTTP %s", resp.Status)
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, f.maxSize+1))
	if err != nil {
		return nil, true, err
	}
	if int64(len(data)) > f.maxSize {
		return nil, false, fmt.Errorf("larger than %d bytes", f.maxSize)
	}
	return data, false, nil
}

// checkText refuses bodies that are not text, or that are web pages: a CDN's error page, a
// captive portal, a login wall.
func checkText(data []byte) error {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("empty")
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return errors.New("not UTF-8 text")
	}
	head := strings.ToLower(string(data[:min(len(data), 1024)]))
	if strings.HasPrefix(strings.TrimSpace(head), "<") || strings.Contains(head, "<html") || strings.Contains(head, "<!doctype") {
		return errors.New("a web page, not a rule file")
	}
	return nil
}

// archive downloads a tar.gz of a repository and returns its regular files by path, without
// the archive's top directory. Files over the size limit map to nil.
func (f *fetcher) archive(ctx context.Context, u string) (map[string][]byte, error) {
	archives := *f
	archives.maxSize = 4 * f.maxSize
	data, err := archives.download(ctx, u, nil)
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", u, err)
	}
	files := map[string][]byte{}
	tr := tar.NewReader(gz)
	budget := 16 * f.maxSize // bounds what a hostile archive can make us decompress
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return files, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", u, err)
		}
		_, name, ok := strings.Cut(hdr.Name, "/")
		if hdr.Typeflag != tar.TypeReg || !ok || name == "" || strings.Contains(name, "..") {
			continue
		}
		if hdr.Size > f.maxSize {
			files[name] = nil
			continue
		}
		if budget -= hdr.Size; budget < 0 {
			return nil, fmt.Errorf("%s: archive too large", u)
		}
		content, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", u, err)
		}
		files[name] = content
	}
}

// resolveCommit finds the commit a source is downloaded at, the head of its branch, in its
// repository's ref advertisement: what git ls-remote reads, which the GitHub API's rate limit
// does not apply to.
func (f *fetcher) resolveCommit(ctx context.Context, s *source) error {
	if s.Repository == "" {
		return nil
	}
	u := strings.TrimSuffix(s.Repository, "/") + "/info/refs?service=git-upload-pack"
	data, err := f.download(ctx, u, nil)
	if err != nil {
		return fmt.Errorf("%s: commit: %w", s.Name, err)
	}
	sha, err := advertisedCommit(data, "refs/heads/"+s.Branch)
	if err != nil {
		return fmt.Errorf("%s: commit: %s: %w", s.Name, u, err)
	}
	s.commit = sha
	return nil
}

// advertisedCommit returns the commit of ref in a ref advertisement of git's smart HTTP
// protocol, version 0, which a server answers a request that asks for no other version. It is
// a series of pkt-lines, each a 4-digit hexadecimal length and "<commit> <ref>", the first ref
// followed by NUL and the server's capabilities; "0000" ends a section.
func advertisedCommit(data []byte, ref string) (string, error) {
	for len(data) > 0 {
		n, err := strconv.ParseUint(string(data[:min(len(data), 4)]), 16, 16)
		switch {
		case err != nil || len(data) < 4 || n > 0 && n < 4:
			return "", errors.New("not a git ref advertisement")
		case n == 0: // flush-pkt
			data = data[4:]
			continue
		case int(n) > len(data):
			return "", errors.New("truncated git ref advertisement")
		}
		line := data[4:n]
		data = data[n:]
		line, _, _ = bytes.Cut(line, []byte{0})
		commit, name, _ := strings.Cut(strings.TrimSuffix(string(line), "\n"), " ")
		if name != ref {
			continue
		}
		if _, err := hex.DecodeString(commit); err != nil || len(commit) != 40 || strings.ToLower(commit) != commit {
			return "", fmt.Errorf("%s: unexpected commit %q", ref, commit[:min(len(commit), 80)])
		}
		return commit, nil
	}
	return "", fmt.Errorf("no %s", ref)
}

// fetchURL is where a source's file is downloaded from.
func (s *source) fetchURL(path string) string {
	base := strings.ReplaceAll(s.Fetch, "{commit}", s.commit)
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		segments[i] = url.PathEscape(seg)
	}
	return base + strings.Join(segments, "/")
}
