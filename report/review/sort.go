package review

import (
	"bufio"
	"container/heap"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

// spillChunkSize bounds how many findings are sorted in memory at once. The
// value is small enough that a repository with tens of thousands of files and
// hundreds of thousands of findings stays comfortably within a fixed memory
// budget, while being large enough to keep the number of merge runs low.
const spillChunkSize = 4096

// maxMergeFanIn bounds how many sorted runs are open at the same time. Large
// repositories produce more runs than the process file descriptor limit would
// tolerate, so runs are merged in passes while the fan-in exceeds this value.
// Every comparison in this package ends with the unique finding key, so the
// final order is a function of the findings alone, not of pass grouping.
const maxMergeFanIn = 64

// newSortedFile sorts the findings in inputPath and returns the path of the
// sorted spill. When dedup is set, findings with the same Key collapse to a
// single record, so the same problem reported by two package variants is
// counted once. The transform, when set, runs on findings in final order.
func (b *Builder) newSortedFile(base, inputPath string, compare func(a, b Finding) int, dedup bool, transform func(Finding) (Finding, error)) (string, error) {
	in, err := os.Open(inputPath)
	if err != nil {
		return "", fmt.Errorf("opening review spill %q: %w", inputPath, err)
	}
	defer in.Close() // #nosec G307

	runs := make([]string, 0)
	buf := make([]Finding, 0, spillChunkSize)
	dec := json.NewDecoder(bufio.NewReaderSize(in, 64*1024))

	flush := func() error {
		if len(buf) == 0 {
			return nil
		}
		sort.Slice(buf, func(i, j int) bool { return compare(buf[i], buf[j]) < 0 })
		run, err := b.newRecordFile(base + "-run")
		if err != nil {
			return err
		}
		for i := range buf {
			if err := run.enc.Encode(buf[i]); err != nil {
				run.close()
				return fmt.Errorf("writing sorted run: %w", err)
			}
		}
		if err := run.closeErr(); err != nil {
			return err
		}
		runs = append(runs, run.file.Name())
		buf = buf[:0]
		return nil
	}

	for {
		var f Finding
		err := dec.Decode(&f)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("reading review spill: %w", err)
		}
		buf = append(buf, f)
		if len(buf) >= spillChunkSize {
			if err := flush(); err != nil {
				return "", err
			}
		}
	}
	if err := flush(); err != nil {
		return "", err
	}

	merged, err := b.mergeAll(base, runs, compare)
	if err != nil {
		return "", err
	}

	out, err := b.newRecordFile(base)
	if err != nil {
		return "", err
	}
	if err := b.mergeRunsInto([]string{merged}, compare, dedup, transform, out); err != nil {
		out.close()
		return "", err
	}
	if err := out.closeErr(); err != nil {
		return "", err
	}
	return out.file.Name(), nil
}

// mergeAll reduces the sorted runs to a single run, merging in passes so that
// at most maxMergeFanIn files are open at once.
func (b *Builder) mergeAll(base string, runs []string, compare func(a, b Finding) int) (string, error) {
	if len(runs) == 0 {
		empty, err := b.newRecordFile(base + "-empty")
		if err != nil {
			return "", err
		}
		if err := empty.closeErr(); err != nil {
			return "", err
		}
		return empty.file.Name(), nil
	}

	current := runs
	for len(current) > maxMergeFanIn {
		next := make([]string, 0, (len(current)+maxMergeFanIn-1)/maxMergeFanIn)
		for start := 0; start < len(current); start += maxMergeFanIn {
			end := min(start+maxMergeFanIn, len(current))
			out, err := b.newRecordFile(base + "-merge")
			if err != nil {
				return "", err
			}
			if err := b.mergeRunsInto(current[start:end], compare, false, nil, out); err != nil {
				out.close()
				return "", err
			}
			if err := out.closeErr(); err != nil {
				return "", err
			}
			next = append(next, out.file.Name())
		}
		current = next
	}
	return current[0], nil
}

// mergeRunsInto merges sorted runs into out. When dedup is set, records whose
// Key matches the previously written record are dropped. The transform runs in
// final order, so it may rely on findings of one file arriving together when
// the comparator is location based.
func (b *Builder) mergeRunsInto(runs []string, compare func(a, b Finding) int, dedup bool, transform func(Finding) (Finding, error), out *recordFile) error {
	merger := &runMerger{runs: runs, compare: compare}
	if err := merger.open(); err != nil {
		return err
	}
	defer merger.close()

	lastKey := ""
	haveLast := false
	for {
		f, ok, err := merger.next()
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		if dedup && haveLast && f.Key == lastKey {
			continue
		}
		if transform != nil {
			if f, err = transform(f); err != nil {
				return err
			}
		}
		if err := out.enc.Encode(f); err != nil {
			return fmt.Errorf("writing sorted review spill: %w", err)
		}
		lastKey = f.Key
		haveLast = true
	}
	return nil
}

// eachFinding streams the findings of a newline-delimited JSON spill.
func eachFinding(path string, fn func(Finding) error) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening review spill %q: %w", path, err)
	}
	defer f.Close() // #nosec G307

	dec := json.NewDecoder(bufio.NewReaderSize(f, 64*1024))
	for {
		var finding Finding
		err := dec.Decode(&finding)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading review spill %q: %w", path, err)
		}
		if err := fn(finding); err != nil {
			return err
		}
	}
}

type runReader struct {
	file *os.File
	dec  *json.Decoder
}

type runEntry struct {
	finding Finding
	reader  int
}

type runHeap struct {
	entries []runEntry
	compare func(a, b Finding) int
}

func (h runHeap) Len() int { return len(h.entries) }
func (h runHeap) Less(i, j int) bool {
	if c := h.compare(h.entries[i].finding, h.entries[j].finding); c != 0 {
		return c < 0
	}
	// Comparisons end with the unique finding key, so this tie-break only
	// matters for records that are identical anyway.
	return h.entries[i].reader < h.entries[j].reader
}
func (h runHeap) Swap(i, j int) { h.entries[i], h.entries[j] = h.entries[j], h.entries[i] }
func (h *runHeap) Push(x any)   { h.entries = append(h.entries, x.(runEntry)) }
func (h *runHeap) Pop() any {
	old := h.entries
	n := len(old)
	entry := old[n-1]
	h.entries = old[:n-1]
	return entry
}

type runMerger struct {
	runs    []string
	compare func(a, b Finding) int
	readers []*runReader
	heap    *runHeap
}

func (m *runMerger) open() error {
	m.readers = make([]*runReader, 0, len(m.runs))
	for _, path := range m.runs {
		f, err := os.Open(path)
		if err != nil {
			m.close()
			return fmt.Errorf("opening sorted run %q: %w", path, err)
		}
		m.readers = append(m.readers, &runReader{
			file: f,
			dec:  json.NewDecoder(bufio.NewReaderSize(f, 64*1024)),
		})
	}
	m.heap = &runHeap{compare: m.compare}
	for i, r := range m.readers {
		var f Finding
		err := r.dec.Decode(&f)
		if err == io.EOF {
			continue
		}
		if err != nil {
			m.close()
			return fmt.Errorf("reading sorted run: %w", err)
		}
		heap.Push(m.heap, runEntry{finding: f, reader: i})
	}
	return nil
}

func (m *runMerger) next() (Finding, bool, error) {
	if m.heap.Len() == 0 {
		return Finding{}, false, nil
	}
	entry := heap.Pop(m.heap).(runEntry)
	advanced := entry.finding
	r := m.readers[entry.reader]
	var next Finding
	err := r.dec.Decode(&next)
	if err != nil && err != io.EOF {
		return Finding{}, false, fmt.Errorf("reading sorted run: %w", err)
	}
	if err == nil {
		heap.Push(m.heap, runEntry{finding: next, reader: entry.reader})
	}
	return advanced, true, nil
}

func (m *runMerger) close() {
	for _, r := range m.readers {
		_ = r.file.Close()
	}
	m.readers = nil
}
