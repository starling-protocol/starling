package sync_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/starling-protocol/starling/sync"

	"github.com/stretchr/testify/assert"
)

func TestCodingDeltas(t *testing.T) {
	random := rand.New(rand.NewSource(1234))
	modelA := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)
	msg1 := modelA.NewMessage([]byte("hello"), nil)

	modelB := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)
	msg2 := modelB.NewMessage([]byte("hi"), nil)

	deltas := sync.Deltas{}
	deltas = append(deltas, *sync.NewDelta(modelA.PublicKey, sync.Version(1), []byte("hello"), nil, modelA.NodeStates[modelA.PublicKey][msg1].Signature))
	deltas = append(deltas, *sync.NewDelta(modelB.PublicKey, sync.Version(1), []byte("hi"), nil, modelB.NodeStates[modelB.PublicKey][msg2].Signature))

	bytes := deltas.Encode(nil)
	decodedDeltas, deltaLen, err := sync.DecodeDeltas(bytes)

	assert.NoError(t, err)
	assert.Len(t, bytes, deltaLen)
	assert.EqualValues(t, deltas, decodedDeltas)
}

func TestCodingDeltaAttachedSecret(t *testing.T) {
	random := rand.New(rand.NewSource(1234))
	modelA := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)
	modelB := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)

	var secret [32]byte
	random.Read(secret[:])

	modelA.NewMessage([]byte("invitation"), secret[:])

	deltas := modelA.Delta(modelB.Digest())

	assert.Len(t, deltas, 1)
	assert.Equal(t, deltas[0].AttachedSecret, secret[:])

	encoded := deltas.Encode(nil)
	decodedDeltas, deltaLen, err := sync.DecodeDeltas(encoded)
	assert.NoError(t, err)

	assert.Len(t, encoded, deltaLen)
	assert.EqualValues(t, deltas, decodedDeltas)
}

func TestDeltaSignatureVerification(t *testing.T) {
	random := rand.New(rand.NewSource(1234))
	modelA := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)
	modelB := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)

	var secret [32]byte
	random.Read(secret[:])

	modelA.NewMessage([]byte("hello from A"), secret[:])
	delta := modelA.Delta(modelB.Digest())[0]

	encoded := delta.Encode(nil)

	decodedDelta, decodeLen, err := sync.DecodeDelta(encoded)
	assert.NoError(t, err)
	assert.Len(t, encoded, decodeLen)
	assert.Equal(t, delta, *decodedDelta)

	for i := 0; i < len(encoded); i += 1 {
		altered := bytes.Clone(encoded)
		altered[i] += 1

		_, _, err := sync.DecodeDelta(altered)
		assert.Errorf(t, err, "Expected error after altering byte %d", i)
	}
}

func FuzzDecodingDelta(f *testing.F) {
	random := rand.New(rand.NewSource(1234))
	modelA := sync.NewModel(newPrivateKey(f, random), sync.ModelTypeLink)
	msg1 := modelA.NewMessage([]byte("hello"), nil)

	delta := sync.NewDelta(modelA.PublicKey, sync.Version(1), []byte("hello"), nil, modelA.NodeStates[modelA.PublicKey][msg1].Signature)
	f.Add(delta.Encode(nil))

	f.Fuzz(func(t *testing.T, bytes []byte) {
		assert.NotPanics(t, func() {
			sync.DecodeDelta(bytes)
		})
	})

}
