package redisro

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// Client is a minimal, pure-stdlib RESP client that speaks ONLY the read
// commands required by the read-only Redis tool: GET, SCAN, EXISTS, TTL. It is
// the production implementation of ReadClient.
//
// By construction there is no method that emits a write/destructive command —
// the command verbs are hard-coded string literals in this file.
type Client struct {
	addr    string
	timeout time.Duration

	mu   sync.Mutex
	conn net.Conn
	br   *bufio.Reader
}

// Dial returns a Client for the Redis server at addr. The connection is opened
// lazily on first use and reopened automatically after an I/O error.
func Dial(addr string) *Client {
	return &Client{addr: addr, timeout: 5 * time.Second}
}

// Close releases the underlying connection, if any.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *Client) closeLocked() error {
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.br = nil
		return err
	}
	return nil
}

func (c *Client) ensureLocked() error {
	if c.conn != nil {
		return nil
	}
	conn, err := net.DialTimeout("tcp", c.addr, c.timeout)
	if err != nil {
		return fmt.Errorf("dial redis: %w", err)
	}
	c.conn = conn
	c.br = bufio.NewReader(conn)
	return nil
}

// do sends one command and returns the parsed reply. On any I/O error the
// connection is dropped so the next call redials.
func (c *Client) do(ctx context.Context, args ...string) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureLocked(); err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(dl)
	} else {
		_ = c.conn.SetDeadline(time.Now().Add(c.timeout))
	}

	if err := writeCommand(c.conn, args); err != nil {
		c.closeLocked()
		return nil, err
	}
	reply, err := readReply(c.br)
	if err != nil {
		c.closeLocked()
		return nil, err
	}
	return reply, nil
}

// Get implements ReadClient.
func (c *Client) Get(ctx context.Context, key string) (string, bool, error) {
	reply, err := c.do(ctx, "GET", key)
	if err != nil {
		return "", false, err
	}
	if reply == nil {
		return "", false, nil
	}
	s, ok := reply.(string)
	if !ok {
		return "", false, fmt.Errorf("GET: unexpected reply type %T", reply)
	}
	return s, true, nil
}

// Scan implements ReadClient.
func (c *Client) Scan(ctx context.Context, cursor uint64, match string, count int64) ([]string, uint64, error) {
	reply, err := c.do(ctx, "SCAN", strconv.FormatUint(cursor, 10), "MATCH", match, "COUNT", strconv.FormatInt(count, 10))
	if err != nil {
		return nil, 0, err
	}
	arr, ok := reply.([]any)
	if !ok || len(arr) != 2 {
		return nil, 0, fmt.Errorf("SCAN: unexpected reply %v", reply)
	}
	nextStr, ok := arr[0].(string)
	if !ok {
		return nil, 0, fmt.Errorf("SCAN: bad cursor %v", arr[0])
	}
	next, err := strconv.ParseUint(nextStr, 10, 64)
	if err != nil {
		return nil, 0, fmt.Errorf("SCAN: bad cursor %q: %w", nextStr, err)
	}
	rawKeys, ok := arr[1].([]any)
	if !ok {
		return nil, 0, fmt.Errorf("SCAN: bad keys %v", arr[1])
	}
	keys := make([]string, 0, len(rawKeys))
	for _, k := range rawKeys {
		if s, ok := k.(string); ok {
			keys = append(keys, s)
		}
	}
	return keys, next, nil
}

// Exists implements ReadClient.
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	reply, err := c.do(ctx, "EXISTS", key)
	if err != nil {
		return false, err
	}
	n, ok := reply.(int64)
	if !ok {
		return false, fmt.Errorf("EXISTS: unexpected reply type %T", reply)
	}
	return n > 0, nil
}

// TTL implements ReadClient. Negative Redis TTLs (no expiry / missing key) map
// to a zero duration.
func (c *Client) TTL(ctx context.Context, key string) (time.Duration, error) {
	reply, err := c.do(ctx, "TTL", key)
	if err != nil {
		return 0, err
	}
	n, ok := reply.(int64)
	if !ok {
		return 0, fmt.Errorf("TTL: unexpected reply type %T", reply)
	}
	if n < 0 {
		return 0, nil
	}
	return time.Duration(n) * time.Second, nil
}

func writeCommand(conn net.Conn, args []string) error {
	var b []byte
	b = append(b, '*')
	b = strconv.AppendInt(b, int64(len(args)), 10)
	b = append(b, '\r', '\n')
	for _, a := range args {
		b = append(b, '$')
		b = strconv.AppendInt(b, int64(len(a)), 10)
		b = append(b, '\r', '\n')
		b = append(b, a...)
		b = append(b, '\r', '\n')
	}
	_, err := conn.Write(b)
	return err
}

func readReply(br *bufio.Reader) (any, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 {
		return nil, fmt.Errorf("short reply %q", line)
	}
	prefix := line[0]
	payload := line[1 : len(line)-2] // strip prefix and trailing \r\n

	switch prefix {
	case '+': // simple string
		return payload, nil
	case '-': // error
		return nil, fmt.Errorf("redis error: %s", payload)
	case ':': // integer
		n, err := strconv.ParseInt(payload, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad integer reply %q: %w", payload, err)
		}
		return n, nil
	case '$': // bulk string
		n, err := strconv.Atoi(payload)
		if err != nil {
			return nil, fmt.Errorf("bad bulk length %q: %w", payload, err)
		}
		if n < 0 {
			return nil, nil // nil bulk string
		}
		buf := make([]byte, n+2) // include trailing \r\n
		if _, err := readFull(br, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*': // array
		n, err := strconv.Atoi(payload)
		if err != nil {
			return nil, fmt.Errorf("bad array length %q: %w", payload, err)
		}
		if n < 0 {
			return nil, nil
		}
		out := make([]any, n)
		for i := 0; i < n; i++ {
			out[i], err = readReply(br)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown reply prefix %q", string(prefix))
	}
}

func readFull(br *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := br.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
