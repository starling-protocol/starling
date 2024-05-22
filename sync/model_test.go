package sync_test

import (
	"math/rand"
	"testing"

	"github.com/starling-protocol/starling/sync"

	"github.com/stretchr/testify/assert"
)

func TestInitialDigest(t *testing.T) {
	random := rand.New(rand.NewSource(1234))

	modelA := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)
	assert.Equal(t, modelA.Digest().MaxVersion, sync.Version(0))
}

func TestModelSerialization(t *testing.T) {
	random := rand.New(rand.NewSource(1234))
	priv := newPrivateKey(t, random)
	model := sync.NewModel(priv, sync.ModelTypeLink)
	model.NewMessage([]byte("hello"), nil)
	model.NewMessage([]byte("world"), nil)

	encoded, err := model.EncodeToJSON()
	assert.NoError(t, err)

	decoded, err := sync.DecodeModelFromJSON(encoded)
	assert.NoError(t, err)

	assert.EqualValues(t, *model, *decoded)
}

func TestModelNewMessage(t *testing.T) {
	random := rand.New(rand.NewSource(1234))
	priv := newPrivateKey(t, random)
	pub := sync.ExtractNodePublicKey(priv)
	modelA := sync.NewModel(priv, sync.ModelTypeLink)

	assert.Equal(t, modelA.Digest().MaxVersion, sync.Version(0))
	assert.Len(t, modelA.Digest().Nodes, 1)

	version := modelA.NewMessage([]byte("world"), nil)

	assert.Equal(t, sync.Version(1), version)
	assert.Equal(t, modelA.Digest().MaxVersion, sync.Version(1))
	assert.Equal(t, modelA.Digest().Nodes[pub], sync.Version(1))
	assert.Len(t, modelA.Digest().Nodes, 1)
}

func TestMultipleNewMessages(t *testing.T) {
	random := rand.New(rand.NewSource(1234))
	modelA := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)

	msg1 := modelA.NewMessage([]byte("world"), nil)
	msg2 := modelA.NewMessage([]byte("bar"), nil)

	assert.Equal(t, sync.Version(1), msg1)
	assert.Equal(t, sync.Version(2), msg2)

	assert.Equal(t, modelA.Digest().MaxVersion, sync.Version(2))
	assert.Len(t, modelA.Digest().Nodes, 1)
	assert.Len(t, modelA.NodeStates[modelA.PublicKey], 2)
}

func TestDeltaEmptyDigest(t *testing.T) {
	random := rand.New(rand.NewSource(1234))
	modelA := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)

	value := []byte("world")

	modelA.NewMessage([]byte(value), nil)

	emptyDigest := sync.NewDigest()
	delta := modelA.Delta(emptyDigest)

	assert.Len(t, delta, 1)
	assert.Len(t, delta[0].Signature, 64)
	assert.Equal(t, modelA.PublicKey, delta[0].PublicKey)
	assert.Equal(t, value, delta[0].Value)
	assert.Equal(t, sync.Version(1), delta[0].Version)
}

func TestDeltaWithoutMerge(t *testing.T) {
	random := rand.New(rand.NewSource(1234))
	modelA := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)

	modelA.NewMessage([]byte("hello from A"), nil)
	modelA.NewMessage([]byte("another from A"), nil)

	modelB := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)
	modelB.NewMessage([]byte("hello from B"), nil)

	deltaA := modelA.Delta(modelB.Digest())

	assert.Len(t, deltaA, 2)

	assert.Equal(t, deltaA[0].PublicKey, modelA.PublicKey)
	assert.Equal(t, deltaA[0].Value, []byte("hello from A"))
	assert.Equal(t, deltaA[0].Version, sync.Version(1))

	assert.Equal(t, deltaA[1].PublicKey, modelA.PublicKey)
	assert.Equal(t, deltaA[1].Value, []byte("another from A"))
	assert.Equal(t, deltaA[1].Version, sync.Version(2))
}

func TestTwoNodeMerge(t *testing.T) {
	random := rand.New(rand.NewSource(1234))

	modelA := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)

	modelA.NewMessage([]byte("world"), nil)
	modelA.NewMessage([]byte("you"), nil)

	modelB := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)
	modelB.NewMessage([]byte("there"), nil)

	deltaA := modelA.Delta(modelB.Digest())
	modelB.Merge(modelA.PublicKey, deltaA)
	deltaB := modelB.Delta(modelA.Digest())

	assert.Len(t, deltaA, 2)
	assert.Len(t, modelB.NodeStates, 2)
	assert.Len(t, deltaB, 1)

	assert.Len(t, deltaB[0].Signature, 64)
	assert.Equal(t, modelB.PublicKey, deltaB[0].PublicKey)
	assert.Equal(t, []byte("there"), deltaB[0].Value)
	assert.Equal(t, sync.Version(1), deltaB[0].Version)

}

func TestThreeNodeTransitiveMerge(t *testing.T) {
	random := rand.New(rand.NewSource(1234))

	modelA := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeGroup)
	modelB := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeGroup)
	modelC := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeGroup)

	modelA.NewMessage([]byte("world"), nil)
	modelB.NewMessage([]byte("you"), nil)

	deltaA := modelA.Delta(modelC.Digest())
	modelC.Merge(modelA.PublicKey, deltaA)

	deltaB := modelB.Delta(modelC.Digest())
	modelC.Merge(modelB.PublicKey, deltaB)

	deltaCA := modelC.Delta(modelA.Digest())
	modelA.Merge(modelC.PublicKey, deltaCA)

	deltaCB := modelC.Delta(modelB.Digest())
	modelB.Merge(modelC.PublicKey, deltaCB)

	assert.EqualValues(t, modelA.NodeStates, modelB.NodeStates)
	assert.EqualValues(t, modelB.NodeStates, modelC.NodeStates)
	assert.EqualValues(t, modelC.NodeStates, modelA.NodeStates)
}

func TestRepeatedMerge(t *testing.T) {
	random := rand.New(rand.NewSource(1234))

	modelA := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)
	modelB := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)

	modelA.NewMessage([]byte("first"), nil)

	delta1 := modelA.Delta(modelB.Digest())
	modelB.Merge(modelA.PublicKey, delta1)

	modelA.NewMessage([]byte("second"), nil)
	modelA.NewMessage([]byte("third"), nil)

	digest2 := modelB.Digest()
	delta2 := modelA.Delta(digest2)
	modelB.Merge(modelA.PublicKey, delta2)

	assert.EqualValues(t, digest2.Nodes, sync.DigestNodes{modelB.PublicKey: 0, modelA.PublicKey: 3})

	assert.Len(t, delta2, 2)
	assert.Len(t, delta2[0].Signature, 64)
	assert.Equal(t, modelA.PublicKey, delta2[0].PublicKey)
	assert.Equal(t, []byte("second"), delta2[0].Value)
	assert.Equal(t, sync.Version(2), delta2[0].Version)
	assert.Len(t, delta2[1].Signature, 64)
	assert.Equal(t, modelA.PublicKey, delta2[1].PublicKey)
	assert.Equal(t, []byte("third"), delta2[1].Value)
	assert.Equal(t, sync.Version(3), delta2[1].Version)

	assert.Len(t, modelB.NodeStates[modelA.PublicKey], 3)
	assert.Equal(t, modelB.NodeStates[modelA.PublicKey][1].Value, []byte("first"))
	assert.Equal(t, modelB.NodeStates[modelA.PublicKey][2].Value, []byte("second"))
	assert.Equal(t, modelB.NodeStates[modelA.PublicKey][3].Value, []byte("third"))

	assert.EqualValues(t, modelA.NodeStates, modelB.NodeStates)
}
