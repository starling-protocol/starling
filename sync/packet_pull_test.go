package sync_test

import (
	"math/rand"
	"testing"

	"github.com/starling-protocol/starling/sync"

	"github.com/stretchr/testify/assert"
)

func TestCodingPullSyncPacket(t *testing.T) {
	seed := rand.NewSource(rand.Int63())
	random := rand.New(seed)
	t.Logf("Testing with seed: %d", seed.Int63())

	model := sync.NewModel(newPrivateKey(t, random), sync.ModelTypeLink)

	t.Run("EmptyPullSyncPacket", func(t *testing.T) {
		packet, err := model.NewPullPacket()
		assert.NoError(t, err)

		encoded := packet.Encode()
		decodedPacket, err := sync.DecodePullPacket(encoded)

		assert.NoError(t, err)
		assert.Equal(t, packet, decodedPacket)
	})

	model.NewMessage([]byte("hello"), nil)

	t.Run("SingleMessagePullSyncPacket", func(t *testing.T) {
		packet, err := model.NewPullPacket()
		assert.NoError(t, err)

		encoded := packet.Encode()
		decodedPacket, err := sync.DecodePullPacket(encoded)

		assert.NoError(t, err)
		assert.Equal(t, packet, decodedPacket)
	})
}
