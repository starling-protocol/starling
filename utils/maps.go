package utils

import (
	"math/rand"
	"sort"
)

type mapKeys[K mapKey] struct {
	keys []K
}

// Len implements sort.Interface.
func (mk mapKeys[K]) Len() int {
	return len(mk.keys)
}

// Less implements sort.Interface.
func (mk mapKeys[K]) Less(i int, j int) bool {
	return mk.keys[i] < mk.keys[j]
}

// Swap implements sort.Interface.
func (mk mapKeys[K]) Swap(i int, j int) {
	mk.keys[j], mk.keys[i] = mk.keys[i], mk.keys[j]
}

type mapKey interface {
	~int | ~int64 | ~uint64 | ~int32 | ~uint32 | ~string
}

// ShuffleMapKeys returns a slice of all the keys in the map sorted in a pseudorandom order
func ShuffleMapKeys[K mapKey, V any](random *rand.Rand, m map[K]V) []K {
	mk := mapKeys[K]{
		keys: make([]K, 0, len(m)),
	}

	for key := range m {
		mk.keys = append(mk.keys, key)
	}

	sort.Sort(mk)
	random.Shuffle(len(mk.keys), mk.Swap)

	return mk.keys
}
