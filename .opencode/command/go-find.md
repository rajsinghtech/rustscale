---
description: Search the Go reference tree (tailscale) for types, function declarations, or any pattern. Prevents reading entire Go files just to locate a definition.
agent: build
---

When you need to find a Go type, function, or struct definition, use `tools/go-find.sh` instead of reading the full file. Examples:

- `tools/go-find.sh -t "Hostinfo"` — find where `type Hostinfo struct` is defined
- `tools/go-find.sh -f "Listen" tsnet/` — find `func Listen` definitions in tsnet/
- `tools/go-find.sh "captivePortal"` — grep for any use of "captivePortal" in Go sources
- `tools/go-find.sh -x "NewDirect" magicsock/` — exact match for "NewDirect" in magicsock/

Then use `tools/where.sh` to get precise line numbers in the found file, and read a narrow offset/limit window.

Arguments: $ARGUMENTS
