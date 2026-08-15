// Package chain replays the HMAC chain in a signed log file and reports what it finds.
//
// It replays chains, reports each segment's closing MAC, and names the breaks. Deciding what a break MEANS
// belongs to the caller: this package knows nothing about anchors, witnesses, or who is accusing whom.
//
// See SPEC.md section 3 for the format and section 7 for the procedures implemented here.
package chain

import (
	"bufio"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// KeyFunc supplies the HMAC key for one segment. It is called once per segment, after that segment's start
// line has been read, so a caller deriving per file keys can answer from the chain id and file number the
// file states about itself. Returning nil means "no key for this segment", which is reported rather than
// assumed away.
type KeyFunc func(chainID string, seq uint64) []byte

// StaticKey adapts one fixed key to KeyFunc, for logs signed with a single passphrase.
func StaticKey(key []byte) KeyFunc {
	return func(string, uint64) []byte { return key }
}

// Segment is one chain segment: everything between a start line and the next one, which in an unrotated
// file is the whole file.
type Segment struct {
	ChainV    string // "" for a format version 1 file, which carries no continuity fields
	ChainID   string
	Seq       uint64
	PrevMAC   string // the predecessor's closing MAC as CLAIMED by this segment's start line
	FinalMAC  string // this segment's own closing MAC, which its successor must claim
	LineCount uint64
	FirstLine int // 1 based line number of the start line within its file
	LastLine  int
	Source    string // the file this segment was read from
}

// Issue is one problem found while replaying. Line is 1 based within Source, or 0 when the issue is about
// the file or the set rather than about a line.
type Issue struct {
	Source string
	Line   int
	Reason string
}

func (i Issue) String() string {
	if i.Line > 0 {
		return fmt.Sprintf("%s line %d: %s", i.Source, i.Line, i.Reason)
	}
	return fmt.Sprintf("%s: %s", i.Source, i.Reason)
}

// Result is what a verification found.
type Result struct {
	Segments  []Segment
	Issues    []Issue
	LineCount int
	Files     []string
	// Truncated reports that replay stopped before the end, which happens only under StopOnFirst.
	//
	// A caller MUST NOT read a truncated result as "no continuity problems". A segment that was only
	// partly replayed has no closing MAC to compare against its successor's claim, so the cross file checks
	// are SKIPPED entirely rather than run on incomplete data. Running them anyway invents findings: the
	// partial segment goes missing from the set, and a single edited line then reports as a deleted file,
	// which sends an investigator hunting for a deletion that never happened.
	Truncated bool
}

// OK reports a clean verification.
func (r *Result) OK() bool { return len(r.Issues) == 0 }

// Options tunes a verification.
type Options struct {
	// AllowUnsigned downgrades an unsigned line from a violation to a skipped line. Off by default: in a
	// log that is supposed to be signed, an unsigned line is the most interesting line in the file.
	AllowUnsigned bool
	// StopOnFirst returns as soon as something is wrong, for callers that only need a yes or no.
	StopOnFirst bool
	// OnLine, when set, is called for every verified line with the chain MAC the chain reached there.
	// lineInSegment counts from 1 at the segment's start line, which is exactly how an anchor counts, so a
	// caller checking a file against an anchor that commits to a PREFIX can capture the MAC at the
	// committed line without this package needing to know anchors exist.
	OnLine func(chainID string, seq, lineInSegment uint64, mac string)
}

// macField is the format version 2 wire name for the per line HMAC chain value, and sigFieldV1 is the
// frozen version 1 name. Files written under the old name exist on disks nobody controls and are read
// forever; no new file writes it.
const macField = `,"mac":"`
const sigFieldV1 = `,"sig":"`

// VerifyReader replays every chain segment in r.
func VerifyReader(source string, r io.Reader, keyFor KeyFunc, opt Options) *Result {
	res := &Result{Files: []string{source}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	var (
		prevMAC = make([]byte, 32)
		key     []byte
		cur     *Segment
		lineNum int
	)
	add := func(line int, reason string) bool {
		res.Issues = append(res.Issues, Issue{Source: source, Line: line, Reason: reason})
		return !opt.StopOnFirst
	}
	// stop ends a replay early. The partial segment is still recorded so that a caller can see what was
	// read, and Truncated is set so that nobody mistakes an unfinished pass for a clean one.
	stop := func() *Result {
		res.Truncated = true
		if cur != nil {
			cur.LastLine = lineNum
			res.Segments = append(res.Segments, *cur)
			cur = nil
		}
		return res
	}

	for sc.Scan() {
		raw := sc.Text()
		if strings.TrimSpace(raw) == "" {
			continue
		}
		lineNum++
		res.LineCount++

		if !strings.HasSuffix(raw, "}") {
			if opt.AllowUnsigned {
				continue
			}
			if !add(lineNum, "malformed line, no closing brace") {
				return stop()
			}
			continue
		}
		withoutClose := raw[:len(raw)-1]
		// The LAST occurrence, because a log message may legitimately contain this text and the authentic
		// field is always the final one.
		fieldLen := len(macField)
		idx := strings.LastIndex(withoutClose, macField)
		if idx < 0 {
			// The frozen version 1 name. Both constants happen to be 8 bytes, but the length is taken from
			// the constant that matched, so a future name change cannot silently misalign the parse.
			idx = strings.LastIndex(withoutClose, sigFieldV1)
			fieldLen = len(sigFieldV1)
		}
		if idx < 0 {
			if opt.AllowUnsigned {
				continue
			}
			if !add(lineNum, "missing chain mac") {
				return stop()
			}
			continue
		}
		macPart := withoutClose[idx+fieldLen:]
		if len(macPart) != 65 { // 64 hex characters plus the closing quote
			if !add(lineNum, fmt.Sprintf("malformed chain mac, %d characters", len(macPart))) {
				return stop()
			}
			continue
		}
		stated := macPart[:64]
		signable := withoutClose[:idx]

		if strings.Contains(raw, `"chain_init":"1"`) {
			// A new segment starts here. Close the previous one and pick up this one's key: a per file key
			// can only be chosen once the file has said which file it is.
			if cur != nil {
				cur.LastLine = lineNum - 1
				res.Segments = append(res.Segments, *cur)
			}
			seq, _ := strconv.ParseUint(field(raw, "chain_seq"), 10, 64)
			cur = &Segment{
				ChainV:    field(raw, "chain_v"),
				ChainID:   field(raw, "chain_id"),
				Seq:       seq,
				PrevMAC:   firstNonEmpty(field(raw, "prev_mac"), field(raw, "prev_sig")),
				FirstLine: lineNum,
				Source:    source,
			}
			prevMAC = make([]byte, 32)
			key = keyFor(cur.ChainID, cur.Seq)
			if len(key) == 0 {
				if !add(lineNum, "no key available for this segment") {
					return stop()
				}
			}
		}
		if cur == nil {
			// Lines before any start line cannot be replayed: the chain they belong to begins somewhere this
			// reader was never given, which usually means the head of the file was removed.
			if !add(lineNum, "signed line before any chain start; the beginning of the file is missing") {
				return stop()
			}
			continue
		}
		if len(key) == 0 {
			continue
		}

		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(signable))
		mac.Write(prevMAC)
		want := mac.Sum(nil)
		if stated != hex.EncodeToString(want) {
			if !add(lineNum, "chain mac mismatch") {
				return stop()
			}
			// Continue from what the FILE claims, not from what this line should have hashed to. One altered
			// line then implicates one line, instead of cascading into a report that condemns every line
			// after it and tells an investigator nothing about where to look. Detection is unaffected: a
			// deletion or an insertion still breaks the very next link either way.
			//
			// This rule is normative. An implementation that continues from the computed value produces a
			// different report for the same evidence. See SPEC.md section 3.3.
			if claimed, derr := hex.DecodeString(stated); derr == nil && len(claimed) == sha256.Size {
				want = claimed
			}
		}
		prevMAC = want
		// The segment's closing MAC is what its SUCCESSOR must claim, so it has to be the value on disk
		// rather than the value that should have been there.
		cur.FinalMAC = hex.EncodeToString(want)
		cur.LineCount++
		cur.LastLine = lineNum
		if opt.OnLine != nil {
			opt.OnLine(cur.ChainID, cur.Seq, cur.LineCount, cur.FinalMAC)
		}
	}
	if err := sc.Err(); err != nil {
		res.Issues = append(res.Issues, Issue{Source: source, Reason: "read error: " + err.Error()})
	}
	if cur != nil {
		res.Segments = append(res.Segments, *cur)
	}
	if lineNum == 0 {
		res.Issues = append(res.Issues, Issue{Source: source, Reason: "the file holds no lines"})
	}
	return res
}

// VerifyFile replays one file, transparently reading .gz.
func VerifyFile(path string, keyFor KeyFunc, opt Options) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, gerr := gzip.NewReader(f)
		if gerr != nil {
			return nil, fmt.Errorf("open gzip stream: %w", gerr)
		}
		defer gz.Close()
		r = gz
	}
	return VerifyReader(filepath.Base(path), r, keyFor, opt), nil
}

// VerifyDir replays every signed log file in dir and then checks that the segments form one unbroken
// chain.
//
// SYMLINKS ARE SKIPPED, and that is not a detail. Producers keep a stable name such as "sc-conn-audit.jsonl"
// as a symlink to whichever timestamped file is current, so a verifier that walks a directory naively reads
// the live file twice and reports a chain that restarts in the middle of its own run: a false alarm on a
// healthy log, which is the fastest way to teach people to ignore the tool.
func VerifyDir(dir string, keyFor KeyFunc, opt Options) (*Result, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		name := e.Name()
		lower := strings.ToLower(name)
		if e.IsDir() || !(strings.HasSuffix(lower, ".jsonl") || strings.HasSuffix(lower, ".jsonl.gz")) {
			continue
		}
		full := filepath.Join(dir, name)
		fi, lerr := os.Lstat(full)
		if lerr != nil || fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		paths = append(paths, full)
	}
	if len(paths) == 0 {
		return nil, errors.New("no signed log files found in " + dir)
	}
	sort.Strings(paths)

	combined := &Result{}
	for _, p := range paths {
		one, ferr := VerifyFile(p, keyFor, opt)
		if ferr != nil {
			combined.Issues = append(combined.Issues, Issue{Source: filepath.Base(p), Reason: ferr.Error()})
			continue
		}
		combined.Files = append(combined.Files, one.Files...)
		combined.Segments = append(combined.Segments, one.Segments...)
		combined.Issues = append(combined.Issues, one.Issues...)
		combined.LineCount += one.LineCount
		combined.Truncated = combined.Truncated || one.Truncated
	}
	// The cross file checks need every segment's true closing MAC, which a truncated replay does not have.
	// Running them anyway is worse than not running them: the partially replayed segment is absent or
	// incomplete, so one edited line reports as a DELETED FILE, and an investigator goes looking for a
	// deletion that never happened. See Result.Truncated.
	if !combined.Truncated {
		combined.Issues = append(combined.Issues, LinkIssues(combined.Segments)...)
	}
	return combined, nil
}

// LinkIssues checks that segments form one unbroken chain: consecutive numbering and, for each, a claimed
// predecessor matching the previous segment's closing MAC.
//
// This is the check that makes deleting a WHOLE FILE visible. Every individual file can verify perfectly
// and the set can still be missing a week of history, which is exactly what an attacker with file access
// would attempt first.
//
// Format version 1 files carry no continuity fields, so they are ordered and counted but not linked. Saying
// nothing is honest there, whereas reporting a break in a log that never claimed to link would be a false
// accusation.
func LinkIssues(segments []Segment) []Issue {
	var issues []Issue
	byChain := map[string][]Segment{}
	var order []string
	for _, s := range segments {
		if s.ChainV == "" {
			continue
		}
		if _, seen := byChain[s.ChainID]; !seen {
			order = append(order, s.ChainID)
		}
		byChain[s.ChainID] = append(byChain[s.ChainID], s)
	}
	for _, id := range order {
		segs := byChain[id]
		sort.Slice(segs, func(i, j int) bool { return segs[i].Seq < segs[j].Seq })
		for i, s := range segs {
			if i == 0 {
				if s.Seq != 0 && s.PrevMAC == "" {
					issues = append(issues, Issue{Source: s.Source, Line: s.FirstLine,
						Reason: fmt.Sprintf("chain %s starts at file %d with no predecessor named; earlier files are missing", short(id), s.Seq)})
				}
				continue
			}
			prev := segs[i-1]
			if s.Seq != prev.Seq+1 {
				issues = append(issues, Issue{Source: s.Source, Line: s.FirstLine,
					Reason: fmt.Sprintf("chain %s jumps from file %d to file %d; %d file(s) are missing", short(id), prev.Seq, s.Seq, s.Seq-prev.Seq-1)})
			}
			if s.PrevMAC != prev.FinalMAC {
				issues = append(issues, Issue{Source: s.Source, Line: s.FirstLine,
					Reason: fmt.Sprintf("chain %s file %d claims a predecessor that file %d does not match; a file has been altered, replaced or reordered", short(id), s.Seq, prev.Seq)})
			}
		}
	}
	return issues
}

// SegmentAt returns the segment covering a given chain and file number, which is how a caller checks a file
// against an anchor that names one.
func (r *Result) SegmentAt(chainID string, seq uint64) (Segment, bool) {
	for _, s := range r.Segments {
		if s.ChainID == chainID && s.Seq == seq {
			return s, true
		}
	}
	return Segment{}, false
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// field pulls a top level string value out of a signed line. The line is signed as raw bytes, so it is read
// as raw bytes: running it through a JSON decoder would risk verifying one thing and reporting another.
func field(line, name string) string {
	key := `"` + name + `":"`
	i := strings.Index(line, key)
	if i < 0 {
		return ""
	}
	rest := line[i+len(key):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}
