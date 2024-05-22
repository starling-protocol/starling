package network_layer_test

import (
	"math/rand"
	"testing"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/network_layer"

	"github.com/stretchr/testify/assert"
)

func newSESSPacket(t testing.TB, random *rand.Rand, message []byte) *network_layer.SESSPacket {
	sessID := device.SessionID(random.Uint64())

	nonce := make([]byte, 12)
	if _, err := random.Read(nonce); err != nil {
		t.Fatal("failed to read random bytes")
	}

	cipher := make([]byte, len(message)+16)
	if _, err := random.Read(cipher); err != nil {
		t.Fatal("failed to read random bytes")
	}

	return &network_layer.SESSPacket{
		SessionID: sessID,
		Nonce:     nonce,
		Cipher:    cipher,
	}
}

func FuzzCodingSESS(f *testing.F) {
	random := rand.New(rand.NewSource(1234))

	f.Add([]byte("hello"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, message []byte) {
		sess := newSESSPacket(t, random, message)

		assert.NotNil(t, sess)

		encoded := sess.EncodePacket()
		assert.Len(t, encoded, 41+len(message))

		decoded, err := network_layer.DecodeSESS(encoded)
		assert.NoError(t, err, "failed to decode SESS packet")

		assert.Equal(t, sess, decoded)
	})
}

func FuzzDecodingSESS(f *testing.F) {
	random := rand.New(rand.NewSource(1234))

	f.Add(newSESSPacket(f, random, []byte("hello")).EncodePacket())

	f.Fuzz(func(t *testing.T, bytes []byte) {
		assert.NotPanics(t, func() {
			network_layer.DecodeSESS(bytes)
		})
	})
}
