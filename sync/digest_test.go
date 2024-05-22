package sync_test

import (
	"crypto/ed25519"
	"math/rand"
	"testing"

	"github.com/starling-protocol/starling/sync"

	"github.com/stretchr/testify/assert"
)

func TestIntersectingNodes(t *testing.T) {
	random := rand.New(rand.NewSource(1234))

	key0 := newPublicKey(t, random)
	key1 := newPublicKey(t, random)
	key2 := newPublicKey(t, random)
	key3 := newPublicKey(t, random)

	digestA := sync.NewDigest()
	digestA.IncrementNode(key0)
	digestA.IncrementNode(key1)
	digestA.IncrementNode(key2)

	digestB := sync.NewDigest()
	digestB.IncrementNode(key1)
	digestB.IncrementNode(key2)
	digestB.IncrementNode(key3)

	intersectAB := digestA.IntersectingNodes(digestB)
	intersectBA := digestB.IntersectingNodes(digestA)

	assert.ElementsMatch(t, intersectAB, intersectBA)
	assert.Len(t, intersectAB, 2)
	assert.Contains(t, intersectAB, key1)
	assert.Contains(t, intersectAB, key2)
}

func TestSubtractNodes(t *testing.T) {
	random := rand.New(rand.NewSource(1234))

	key0 := newPublicKey(t, random)
	key1 := newPublicKey(t, random)
	key2 := newPublicKey(t, random)
	key3 := newPublicKey(t, random)

	digestA := sync.NewDigest()
	digestA.IncrementNode(key0)
	digestA.IncrementNode(key1)
	digestA.IncrementNode(key2)

	digestB := sync.NewDigest()
	digestB.IncrementNode(key1)
	digestB.IncrementNode(key2)
	digestB.IncrementNode(key3)

	bSubA := digestB.SubtractNodes(digestA)
	aSubB := digestA.SubtractNodes(digestB)
	assert.EqualValues(t, bSubA, []sync.NodePublicKey{key3})
	assert.EqualValues(t, aSubB, []sync.NodePublicKey{key0})
}

func TestCodingDigest(t *testing.T) {
	random := rand.New(rand.NewSource(1234))

	senderKey := newPublicKey(t, random)
	key0 := newPublicKey(t, random)
	key1 := newPublicKey(t, random)

	digest := sync.NewDigest()
	digest.IncrementNode(senderKey)
	digest.IncrementNode(key0)
	digest.IncrementNode(key1)

	encoded := digest.EncodeWithoutSender(nil, senderKey)

	decoded, read, err := sync.DecodeDigest(encoded)
	assert.NoError(t, err)
	assert.Len(t, encoded, read)

	assert.Equal(t, decoded.MaxVersion, digest.MaxVersion)
	assert.Len(t, decoded.Nodes, 2)
}

func FuzzDecodingDigest(f *testing.F) {
	random := rand.New(rand.NewSource(1234))

	random_digest := [200]byte{}
	if n, err := random.Read(random_digest[:]); n != 200 || err != nil {
		f.Fatal()
	}
	f.Add(random_digest[:])

	_, priv, err := ed25519.GenerateKey(random)
	assert.Nil(f, err)
	model := sync.NewModel(priv, sync.ModelTypeLink)
	buf := []byte{}
	buf = model.Digest().EncodeWithoutSender(buf, newPublicKey(f, random))
	f.Add(buf)

	_, priv, err = ed25519.GenerateKey(random)
	assert.Nil(f, err)
	model = sync.NewModel(priv, sync.ModelTypeLink)
	model.NewMessage([]byte("Test"), nil)
	model.NewMessage([]byte("Another test"), nil)
	buf = []byte{}
	buf = model.Digest().EncodeWithoutSender(buf, newPublicKey(f, random))
	f.Add(buf)

	f.Fuzz(func(t *testing.T, bytes []byte) {
		assert.NotPanics(t, func() {
			sync.DecodeDigest(bytes)
		})
	})
}
