package mcp

import (
	"bytes"
	"context"
	"sync"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// progressNotifier turns build/deploy output lines into MCP progress
// notifications on the calling request's progress token — this is what makes
// a multi-minute pack build visible in the agent instead of looking hung
// (PLAN §5.5: SSE progress is non-negotiable). Notification failures are
// dropped: progress is best-effort and must never fail the operation.
type progressNotifier struct {
	ctx     context.Context
	session *sdkmcp.ServerSession
	token   any

	mu  sync.Mutex
	buf bytes.Buffer
	n   float64
}

// newProgressNotifier returns nil when the client did not ask for progress
// (no token); callers treat nil as "no progress plumbing".
func newProgressNotifier(ctx context.Context, req *sdkmcp.CallToolRequest) *progressNotifier {
	token := req.Params.GetProgressToken()
	if token == nil {
		return nil
	}
	return &progressNotifier{ctx: ctx, session: req.Session, token: token}
}

// Write implements io.Writer over line-buffered notifications.
func (p *progressNotifier) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buf.Write(b)
	for {
		line, err := p.buf.ReadString('\n')
		if err != nil {
			// Partial line: keep it buffered for the next write.
			p.buf.WriteString(line)
			break
		}
		p.sendLocked(line[:len(line)-1])
	}
	return len(b), nil
}

// Stage emits a coarse lifecycle marker ("building", "deploying", ...).
func (p *progressNotifier) Stage(msg string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sendLocked(msg)
}

// Flush emits any buffered partial line.
func (p *progressNotifier) Flush() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.buf.Len() > 0 {
		p.sendLocked(p.buf.String())
		p.buf.Reset()
	}
}

func (p *progressNotifier) sendLocked(msg string) {
	p.n++
	_ = p.session.NotifyProgress(p.ctx, &sdkmcp.ProgressNotificationParams{
		ProgressToken: p.token,
		Progress:      p.n,
		Message:       msg,
	})
}
