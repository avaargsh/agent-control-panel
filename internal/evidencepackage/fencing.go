package evidencepackage

// ReceiptHead is an immutable, content-addressed source receipt pointer.
// The source service remains the only authoritative writer. ACP may compare
// snapshots but must never use this helper as authorization to publish a PR
// or to perform a protected effect.
type ReceiptHead struct {
	TenantID  string
	RunID     string
	Stage     string
	Authority string
	Revision  uint64
	Digest    string
}

type ReceiptDisposition string

const (
	ReceiptInsert  ReceiptDisposition = "INSERT"
	ReceiptReplay  ReceiptDisposition = "IDEMPOTENT_REPLAY"
	ReceiptAdvance ReceiptDisposition = "ADVANCE"
)

func (h ReceiptHead) valid() bool {
	if !identifier(h.TenantID) || !identifier(h.RunID) ||
		!digest(h.Digest) || h.Revision == 0 {
		return false
	}
	for _, stage := range stages {
		if h.Stage == stage.stage && h.Authority == stage.authority {
			return true
		}
	}
	return false
}

// CompareReceiptHead is a pure fail-closed CAS classification for an owner
// service's authoritative row. The owner MUST execute the comparison and
// durable write atomically using a version predicate or row lock. Merely
// calling this function outside that transaction is NOT a version fence.
func CompareReceiptHead(current *ReceiptHead, incoming ReceiptHead) (ReceiptDisposition, error) {
	if !incoming.valid() {
		return "", reject("malformed incoming receipt head")
	}
	if current == nil {
		return ReceiptInsert, nil
	}
	if !current.valid() || current.TenantID != incoming.TenantID ||
		current.RunID != incoming.RunID || current.Stage != incoming.Stage ||
		current.Authority != incoming.Authority {
		return "", reject("receipt source or original Run binding changed")
	}
	if incoming.Revision < current.Revision {
		return "", reject("older receipt cannot replace newer source revision")
	}
	if incoming.Revision == current.Revision {
		if incoming.Digest != current.Digest {
			return "", reject("same revision carries conflicting immutable bytes")
		}
		return ReceiptReplay, nil
	}
	return ReceiptAdvance, nil
}
