package sync_test

import (
	"math/rand"
	"testing"

	"github.com/starling-protocol/starling/sync"

	"github.com/stretchr/testify/assert"
)

func TestCodingPushSyncPacket(t *testing.T) {
	seed := rand.NewSource(rand.Int63())
	random := rand.New(seed)
	t.Logf("Testing with seed: %d", seed.Int63())

	model := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)

	t.Run("EmptyPushSyncPacket", func(t *testing.T) {
		delta := model.Delta(sync.NewDigest())
		assert.Len(t, delta, 0)

		packet := model.NewPushPacket(newPublicKey(t, random), delta)

		encoded := packet.Encode()
		decodedPacket, err := sync.DecodePushPacket(encoded)

		assert.NoError(t, err)
		assert.Equal(t, packet, decodedPacket)
	})

	model.NewMessage([]byte("hello"), nil)

	t.Run("SingleMessagePullSyncPacket", func(t *testing.T) {
		delta := model.Delta(sync.NewDigest())
		assert.Len(t, delta, 1)

		packet := model.NewPushPacket(newPublicKey(t, random), delta)

		encoded := packet.Encode()
		decodedPacket, err := sync.DecodePushPacket(encoded)

		assert.NoError(t, err)
		assert.Equal(t, packet, decodedPacket)
	})
}
