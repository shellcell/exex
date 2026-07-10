package explorer

import "sort"

// SearchCache remembers where an instruction-text search has already found hits,
// and how much of the executable image it has already scanned, for one query.
//
// The disassembly search scans the image in chunks, streaming results back as it
// goes. Repeating the search (n / N) must not rescan: the cache answers "the next
// hit after this address" directly whenever it can, and tracks the scanned range
// so it knows when it holds *every* hit and can stop scanning altogether.
//
// It is bounded. Past CacheCap hits it records that it overflowed and keeps only
// the window nearest the direction of travel, because a query like "mov" matches
// tens of thousands of instructions and the whole point is not to hold them.

// CacheCap bounds how many hits one query's cache retains.
const CacheCap = 100

// SearchHit is a cached match: only the address and the instruction text.
//
// Deliberately *not* the decoded window that found it. Retaining those would pin
// a decoded chunk per hit; a repeat jump re-decodes around the address instead,
// which the service's window cache usually satisfies anyway.
type SearchHit struct {
	Addr uint64
	Text string
}

// CursorMode says where the search cursor sits relative to the hits, which
// decides what "the next one" means when the cursor has run off an end.
type CursorMode uint8

const (
	CursorAtMatch     CursorMode = iota // on a hit (or anywhere in the image)
	CursorAfterEnd                      // ran off the end going forward
	CursorBeforeStart                   // ran off the start going backward
)

// SearchCache is the per-query cache. The zero value is an empty cache for the
// empty query; call Reset before use.
type SearchCache struct {
	query             string
	hits              []SearchHit
	forwardExhausted  bool
	backwardExhausted bool
	scannedLo         int // -1 until anything has been scanned
	scannedHi         int
	overflow          bool
}

// Reset empties the cache for a new query.
func (c *SearchCache) Reset(query string) {
	*c = SearchCache{query: query, scannedLo: -1}
}

// EnsureQuery resets the cache when the query has changed, and reports whether it
// did.
func (c *SearchCache) EnsureQuery(query string) bool {
	if c.query != query {
		c.Reset(query)
		return true
	}
	return false
}

// Query returns the query this cache holds hits for.
func (c *SearchCache) Query() string { return c.query }

// Hits returns the cached hits, in ascending address order.
func (c *SearchCache) Hits() []SearchHit { return c.hits }

// Overflow reports whether more hits were found than the cache can hold, so it
// no longer holds all of them.
func (c *SearchCache) Overflow() bool { return c.overflow }

// Exhausted reports whether scanning in this direction has reached the image's
// end without finding anything more.
func (c *SearchCache) Exhausted(forward bool) bool {
	if forward {
		return c.forwardExhausted
	}
	return c.backwardExhausted
}

// SetExhausted records that a direction has been scanned to its end.
func (c *SearchCache) SetExhausted(forward bool) {
	if forward {
		c.forwardExhausted = true
	} else {
		c.backwardExhausted = true
	}
}

// Add merges freshly found hits, keeping the slice sorted and deduplicated by
// address. Past CacheCap it trims to the window nearest the direction of travel:
// forward keeps the highest addresses, backward the lowest.
//
// Add reorders hits in place.
func (c *SearchCache) Add(hits []SearchHit, forward bool) {
	if len(hits) == 0 {
		return
	}
	// Sorting first is not needed for correctness — the insert below is a binary
	// search either way — but it makes every insert land at the end of c.hits,
	// where the shift is free. Parallel chunk workers report hits in arbitrary
	// order, and a query like "mov" reports thousands at a time; without this the
	// insert degrades to a memmove per hit (~23x slower at 10k).
	sort.Slice(hits, func(i, j int) bool { return hits[i].Addr < hits[j].Addr })
	for _, hit := range hits {
		i := sort.Search(len(c.hits), func(i int) bool { return c.hits[i].Addr >= hit.Addr })
		if i < len(c.hits) && c.hits[i].Addr == hit.Addr {
			continue
		}
		if len(c.hits) >= CacheCap {
			c.overflow = true
		}
		c.hits = append(c.hits, SearchHit{})
		copy(c.hits[i+1:], c.hits[i:])
		c.hits[i] = hit
	}
	if len(c.hits) > CacheCap {
		if forward {
			c.hits = c.hits[len(c.hits)-CacheCap:]
		} else {
			c.hits = c.hits[:CacheCap]
		}
	}
}

// NoteCoverage widens the scanned image range.
func (c *SearchCache) NoteCoverage(lo, hi int) {
	if lo < 0 {
		lo = 0
	}
	if hi < lo {
		hi = lo
	}
	if c.scannedLo < 0 || lo < c.scannedLo {
		c.scannedLo = lo
	}
	if hi > c.scannedHi {
		c.scannedHi = hi
	}
}

// Coverage returns the scanned image range; lo is -1 when nothing was scanned.
func (c *SearchCache) Coverage() (lo, hi int) { return c.scannedLo, c.scannedHi }

// Complete reports whether the cache holds every hit in an image of imgLen bytes:
// the whole image was scanned and nothing was dropped.
func (c *SearchCache) Complete(imgLen int) bool {
	return !c.overflow && c.scannedLo == 0 && c.scannedHi >= imgLen
}

// Next returns the cached hit the search would move to from cur, or ok=false when
// the cache cannot answer and the image must be scanned.
//
// inclusive keeps a hit exactly at cur (the initial Enter); n / N pass false to
// step past it. When the cursor has run off an end, the search wraps to the hit
// at the opposite end.
func (c *SearchCache) Next(cur uint64, mode CursorMode, forward, inclusive bool) (SearchHit, bool) {
	if len(c.hits) == 0 {
		return SearchHit{}, false
	}
	if !forward && mode == CursorAfterEnd {
		return c.hits[len(c.hits)-1], true
	}
	if forward && mode == CursorBeforeStart {
		return c.hits[0], true
	}
	if forward {
		for _, hit := range c.hits {
			if (!inclusive && hit.Addr <= cur) || (inclusive && hit.Addr < cur) {
				continue
			}
			return hit, true
		}
		return SearchHit{}, false
	}
	for i := len(c.hits) - 1; i >= 0; i-- {
		hit := c.hits[i]
		if (!inclusive && hit.Addr >= cur) || (inclusive && hit.Addr > cur) {
			continue
		}
		return hit, true
	}
	return SearchHit{}, false
}

// Boundary returns the outermost cached hit in a direction: the last one going
// forward, the first going backward. It is where an incremental scan resumes.
func (c *SearchCache) Boundary(forward bool) (uint64, bool) {
	if len(c.hits) == 0 {
		return 0, false
	}
	if forward {
		return c.hits[len(c.hits)-1].Addr, true
	}
	return c.hits[0].Addr, true
}
