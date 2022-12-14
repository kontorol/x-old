package quic

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

const (
	defaultBacklog = 128
)

type metadata struct {
	// keepAlive        bool
	keepAlivePeriod  time.Duration
	handshakeTimeout time.Duration
	maxIdleTimeout   time.Duration

	cipherKey []byte
	backlog   int
}

func (l *quicListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keepAlive        = "keepAlive"
		keepAlivePeriod  = "ttl"
		handshakeTimeout = "handshakeTimeout"
		maxIdleTimeout   = "maxIdleTimeout"

		backlog   = "backlog"
		cipherKey = "cipherKey"
	)

	l.md.backlog = mdx.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	if key := mdx.GetString(md, cipherKey); key != "" {
		l.md.cipherKey = []byte(key)
	}

	if mdx.GetBool(md, keepAlive) {
		l.md.keepAlivePeriod = mdx.GetDuration(md, keepAlivePeriod)
		if l.md.keepAlivePeriod <= 0 {
			l.md.keepAlivePeriod = 10 * time.Second
		}
	}
	l.md.handshakeTimeout = mdx.GetDuration(md, handshakeTimeout)
	l.md.maxIdleTimeout = mdx.GetDuration(md, maxIdleTimeout)

	return
}
