package grpc

import (
	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

const (
	defaultBacklog = 128
)

type metadata struct {
	backlog  int
	insecure bool
	path     string
}

func (l *grpcListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		backlog  = "backlog"
		insecure = "grpcInsecure"
		path     = "path"
	)

	l.md.backlog = mdx.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	l.md.insecure = mdx.GetBool(md, insecure)
	l.md.path = mdx.GetString(md, path)
	return
}
