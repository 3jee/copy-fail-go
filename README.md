# copy-fail-go

Go port of [grenkoca](https://github.com/grenkoca)'s Python PoC for **CVE-2026-31431** (copy-fail).

This version automatically enumerates all SUID world-readable binaries on the target and lets you choose which one to exploit interactively.

> **For authorized security research and CTF use only.**

---

## What is CVE-2026-31431 (copy-fail)?

CVE-2026-31431 is a Linux kernel vulnerability that allows an unprivileged user to overwrite arbitrary bytes in read-only, SUID-root files via a race condition in the `splice(2)` path of the AF_ALG (kernel crypto API) socket implementation. Because the write bypasses permission checks on the page cache, a world-readable SUID binary can be patched in-place without write access, leading to local privilege escalation.

**Affected kernels:** See [grenkoca's original advisory](https://github.com/grenkoca) for the full version range.

---

## Differences from the original Python PoC

| | Original (Python) | This repo (Go) |
|---|---|---|
| Language | Python 3 | Go 1.21+ |
| Target | Hardcoded `/usr/bin/su` | Auto-detected from live filesystem scan |
| Target selection | None | Interactive numbered menu |
| Distribution | Script | Single static binary (no runtime deps) |

---

## Requirements

- Linux kernel in the affected version range
- A SUID world-readable binary present on the target (the tool will find them)
- No special privileges required to run

### Build dependencies (on your build machine)

| Tool | Version |
|------|---------|
| Go   | 1.21+   |

---

## Building

### Native Linux build

```bash
git clone https://github.com/3jee/copy-fail-go
cd copy-fail-go
go build -o copy-fail .
```

### Cross-compile from macOS or Windows (targeting Linux x86-64)

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o copy-fail .
```

The `-s -w` flags strip debug info to reduce binary size. `CGO_ENABLED=0` produces a fully static binary with no libc dependency - drop it on any Linux target regardless of glibc version.

### Other architectures

| Target | Command |
|--------|---------|
| Linux ARM64 | `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o copy-fail .` |
| Linux 32-bit x86 | `GOOS=linux GOARCH=386 CGO_ENABLED=0 go build -o copy-fail .` |

---

## Usage

Transfer the binary to the target and execute it (no root required):

```bash
./copy-fail
```

Example session:

```
CVE-2026-31431 (copy-fail) - Go PoC
Based on grenkoca's original PoC

Scanning for SUID world-readable binaries...

SUID world-readable binaries found:
------------------------------------
  [1] /usr/bin/su
  [2] /usr/bin/sudo
  [3] /usr/bin/passwd
  [4] /usr/bin/newgrp

Select target [1-4]: 1

[*] Targeting: /usr/bin/su
[*] Writing 48 bytes to /usr/bin/su...
[+] Write complete. Executing target...
# whoami
root
```

---

## How it works

1. Opens the target SUID binary with `O_RDONLY` - no write permission needed.
2. Creates an `AF_ALG` (`SOCK_SEQPACKET`) socket bound to the `authencesn(hmac(sha256),cbc(aes))` AEAD transform.
3. Sends a crafted `sendmsg` with `MSG_MORE` and SOL_ALG control messages to queue a crypto operation against the target file's page cache entry.
4. Uses `splice(2)` to move pages from the file into the ALG socket, triggering the vulnerable kernel path that writes back modified page cache pages without re-checking file permissions.
5. Repeats for each 4-byte chunk of the payload.
6. Executes the patched binary.

---

## Credits

- **grenkoca** - original Python PoC and vulnerability discovery
- This repo is an unminified Go port with automatic target enumeration
