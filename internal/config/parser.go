// Package config provides configuration parsing, expansion, and validation
// for the CrowdSec Cloudflare list bouncer daemon.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Sentinel errors returned during configuration file syntax parsing.
var (
	ErrInvalidLine           = errors.New("invalid configuration line")
	ErrUnexpectedIndentation = errors.New("unexpected indentation in list item")
)

// ParsedDocument contains key-value pairs and key-list collections extracted
// from a flat YAML-compatible configuration file.
type ParsedDocument struct {
	Scalars map[string]string
	Lists   map[string][]string
}

// ParseDocument scans a configuration stream and organizes flat scalar keys
// and single-level string lists without relying on external YAML libraries.
func ParseDocument(r io.Reader) (*ParsedDocument, error) {
	scanner := bufio.NewScanner(r)
	doc := &ParsedDocument{
		Scalars: make(map[string]string),
		Lists:   make(map[string][]string),
	}

	var activeListKey string
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(rawLine, "  - ") {
			if activeListKey == "" {
				return nil, fmt.Errorf("%w at line %d: list item without parent key", ErrUnexpectedIndentation, lineNumber)
			}
			itemVal := cleanValue(strings.TrimPrefix(rawLine, "  - "))
			doc.Lists[activeListKey] = append(doc.Lists[activeListKey], itemVal)
			continue
		}

		activeListKey = ""

		key, val, found := strings.Cut(trimmed, ":")
		if !found {
			return nil, fmt.Errorf("%w at line %d: missing colon delimiter", ErrInvalidLine, lineNumber)
		}

		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		if key == "" {
			return nil, fmt.Errorf("%w at line %d: empty key", ErrInvalidLine, lineNumber)
		}

		if val == "" {
			activeListKey = key
			doc.Lists[key] = make([]string, 0)
			continue
		}

		doc.Scalars[key] = cleanValue(val)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan configuration: %w", err)
	}

	return doc, nil
}

func cleanValue(raw string) string {
	val := strings.TrimSpace(raw)
	if before, _, found := strings.Cut(val, " #"); found {
		val = strings.TrimSpace(before)
	}
	if len(val) >= 2 {
		first := val[0]
		last := val[len(val)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			val = val[1 : len(val)-1]
		}
	}
	return val
}
