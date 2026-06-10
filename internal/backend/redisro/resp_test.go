package redisro

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeServer accepts one connection, records the command bytes it receives, and
// replies with the canned RESP reply. Loopback only — no external service.
func fakeServer(t *testing.T, reply string) (addr string, gotCmd func() string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	recv := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read exactly one RESP array command (*N ... N bulk strings).
		br := bufio.NewReader(conn)
		line, _ := br.ReadString('\n')
		var b strings.Builder
		b.WriteString(line)
		if strings.HasPrefix(line, "*") {
			n := 0
			for _, c := range strings.TrimSpace(line[1:]) {
				n = n*10 + int(c-'0')
			}
			for i := 0; i < n*2; i++ { // each bulk string is 2 lines: $len and data
				l, _ := br.ReadString('\n')
				b.WriteString(l)
			}
		}
		recv <- b.String()
		conn.Write([]byte(reply))
	}()

	return ln.Addr().String(), func() string {
		select {
		case s := <-recv:
			return s
		case <-time.After(2 * time.Second):
			t.Fatal("server received no command")
			return ""
		}
	}
}

func TestClientGetEncodesAndParses(t *testing.T) {
	addr, gotCmd := fakeServer(t, "$5\r\nalice\r\n")
	c := Dial(addr)
	defer c.Close()

	val, found, err := c.Get(context.Background(), "user:1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found || val != "alice" {
		t.Errorf("Get = %q, %v", val, found)
	}
	cmd := gotCmd()
	if !strings.Contains(cmd, "GET") || !strings.Contains(cmd, "user:1") {
		t.Errorf("command sent = %q, want GET user:1", cmd)
	}
}

func TestClientGetNilIsNotFound(t *testing.T) {
	addr, _ := fakeServer(t, "$-1\r\n")
	c := Dial(addr)
	defer c.Close()

	_, found, err := c.Get(context.Background(), "missing")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Error("nil reply should mean not found")
	}
}

func TestClientExistsParsesInteger(t *testing.T) {
	addr, _ := fakeServer(t, ":1\r\n")
	c := Dial(addr)
	defer c.Close()

	found, err := c.Exists(context.Background(), "user:1")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !found {
		t.Error("Exists should be true for :1 reply")
	}
}

func TestClientTTLParsesSeconds(t *testing.T) {
	addr, _ := fakeServer(t, ":30\r\n")
	c := Dial(addr)
	defer c.Close()

	ttl, err := c.TTL(context.Background(), "user:1")
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	if ttl != 30*time.Second {
		t.Errorf("TTL = %v, want 30s", ttl)
	}
}

func TestClientScanParsesArray(t *testing.T) {
	// SCAN reply: array of [next-cursor, array-of-keys].
	reply := "*2\r\n$1\r\n0\r\n*2\r\n$6\r\nuser:1\r\n$6\r\nuser:2\r\n"
	addr, gotCmd := fakeServer(t, reply)
	c := Dial(addr)
	defer c.Close()

	keys, next, err := c.Scan(context.Background(), 0, "user:*", 100)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if next != 0 {
		t.Errorf("next cursor = %d, want 0", next)
	}
	if len(keys) != 2 || keys[0] != "user:1" {
		t.Errorf("keys = %v", keys)
	}
	if cmd := gotCmd(); !strings.Contains(cmd, "SCAN") || !strings.Contains(cmd, "MATCH") {
		t.Errorf("command = %q, want SCAN ... MATCH ...", cmd)
	}
}
