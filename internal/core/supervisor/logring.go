package supervisor

// A bounded record of what a process last said.
//
// Exported because Brook and AmneziaWG run their own processes rather than going
// through Process, and each was capturing nothing at all: output went to the
// panel's own stderr, unattributed, so a crashed Brook inbound produced a line
// in the journal that named no inbound and reached no health endpoint. Copying
// the buffer into those packages would have copied a wraparound bug that took a
// deliberately-chosen test input to find, so it is shared instead.

// LogRing keeps the most recent lines a process wrote, oldest-first on read.
// The zero value is not usable; call NewLogRing.
type LogRing = ring

// NewLogRing returns a ring holding at most size lines.
func NewLogRing(size int) *LogRing { return newRing(size) }

// Add records one line.
func (r *ring) Add(line string) { r.add(line) }

// Snapshot returns everything held, oldest first.
func (r *ring) Snapshot() []string { return r.snapshot() }

// SnapshotN returns the most recent n lines, oldest first.
func (r *ring) SnapshotN(n int) []string { return r.snapshotN(n) }

// Hint returns a one-line explanation of the most recent failure in the buffer,
// or the raw last line when nothing matches a known signature, or "" when the
// process has said nothing.
func (r *ring) Hint() string { return logHint(r) }
