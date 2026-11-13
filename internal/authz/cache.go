package authz

import (
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"

	"tule.dev/policy"
)

// maxCachedPolicies bounds the parsed policies kept. A principal's
// documents are sent with each of its requests; parsing them is cheap
// beside the request, but a busy test suite repeats the same few documents
// thousands of times.
const maxCachedPolicies = 512

// policyCache keeps parsed identity policies by the SHA-256 of their
// document, the least recently used one dropped when it is full. A
// *policy.Policy is immutable, so one is shared by every request that
// carries its document.
type policyCache struct {
	entries map[[sha256.Size]byte]*list.Element
	order   *list.List
	mu      sync.Mutex
	max     int
}

type cacheEntry struct {
	policy *policy.Policy
	key    [sha256.Size]byte
}

func newPolicyCache(maxEntries int) *policyCache {
	return &policyCache{
		entries: make(map[[sha256.Size]byte]*list.Element),
		order:   list.New(),
		max:     maxEntries,
	}
}

// parse returns the parsed policies of the documents, in order. Identity
// checked every document when it was stored, so a document that does not
// parse is a fault, reported as an error rather than skipped: skipping a
// policy could drop a Deny.
func (c *policyCache) parse(docs []json.RawMessage) ([]*policy.Policy, error) {
	out := make([]*policy.Policy, 0, len(docs))
	for i, doc := range docs {
		p, err := c.get(doc)
		if err != nil {
			return nil, fmt.Errorf("authz: parse identity policy %d: %w", i, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func (c *policyCache) get(doc []byte) (*policy.Policy, error) {
	key := sha256.Sum256(doc)

	c.mu.Lock()
	if e, ok := c.entries[key]; ok {
		c.order.MoveToFront(e)
		p := e.Value.(*cacheEntry).policy
		c.mu.Unlock()
		return p, nil
	}
	c.mu.Unlock()

	p, err := policy.ParseIdentity(doc)
	if err != nil {
		return nil, err //nolint:wrapcheck // parse wraps it with the policy's index
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; !ok {
		c.entries[key] = c.order.PushFront(&cacheEntry{policy: p, key: key})
		for c.order.Len() > c.max {
			last := c.order.Back()
			c.order.Remove(last)
			old := last.Value.(*cacheEntry)
			delete(c.entries, old.key)
		}
	}
	return p, nil
}

// len reports how many policies are cached.
func (c *policyCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
