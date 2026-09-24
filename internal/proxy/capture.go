package proxy

// capture is an io.Writer that keeps the first max bytes written to it and
// counts everything. It is used to record bodies while they stream through the
// proxy; the full body is always forwarded regardless of the capture limit.
type capture struct {
	max   int64
	buf   []byte
	total int64
}

func newCapture(max int64) *capture { return &capture{max: max} }

func (c *capture) Write(p []byte) (int, error) {
	n := len(p)
	c.total += int64(n)
	if room := c.max - int64(len(c.buf)); room > 0 {
		if int64(len(p)) > room {
			p = p[:room]
		}
		c.buf = append(c.buf, p...)
	}
	return n, nil
}
