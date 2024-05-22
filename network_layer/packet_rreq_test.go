package network_layer_test

import (
	"crypto/ecdh"
	"math/rand"
	"testing"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/network_layer"
	"github.com/starling-protocol/starling/network_layer/contact_bitmap"

	"github.com/stretchr/testify/assert"
)

func FuzzCodingRREQ(f *testing.F) {
	random := rand.New(rand.NewSource(1234))

	bitmapResult, err := contact_bitmap.EncodeContactBitmap(random, []device.ContactID{}, device.NewMemoryContactsContainer(), 1)
	if err != nil {
		f.Fatalf("expected no error: %v", err)
	}
	f.Add(uint64(bitmapResult.Seed), uint16(10), []byte(bitmapResult.Bitmap))

	f.Fuzz(func(t *testing.T, _reqID uint64, _ttl uint16, bitmap []byte) {
		if len(bitmap) != contact_bitmap.BITMAP_SIZE {
			return
		}

		reqID := network_layer.RequestID(_reqID)
		ttl := network_layer.TTL(_ttl)

		ephemeralPrivate, err := ecdh.X25519().GenerateKey(random)
		assert.NoError(t, err)
		rreq := network_layer.NewRREQPacket(reqID, ttl, *ephemeralPrivate.PublicKey(), bitmap)

		assert.NotNil(t, rreq)
		assert.Equal(t, reqID, rreq.RequestID)
		assert.Equal(t, ttl, rreq.TTL)
		assert.Equal(t, *ephemeralPrivate.PublicKey(), rreq.EphemeralKey)

		encoded := rreq.EncodePacket()
		assert.Len(t, encoded, 299)

		decoded, err := network_layer.DecodeRREQ(encoded)
		assert.NoError(t, err, "failed to decode RREQ packet")

		assert.Equal(t, rreq, decoded)
	})

}

func FuzzDecodingRREQ(f *testing.F) {
	random := rand.New(rand.NewSource(1234))

	bitmapResult, err := contact_bitmap.EncodeContactBitmap(random, []device.ContactID{}, device.NewMemoryContactsContainer(), 1)
	if err != nil {
		f.Fatalf("expected no error: %v", err)
	}
	ephemeralPrivate, err := ecdh.X25519().GenerateKey(random)
	assert.NoError(f, err)
	rreq := network_layer.NewRREQPacket(network_layer.RequestID(bitmapResult.Seed), network_layer.TTL(10), *ephemeralPrivate.PublicKey(), bitmapResult.Bitmap)
	f.Add(rreq.EncodePacket())

	invalid_rreq := [299]byte{}
	if n, err := random.Read(invalid_rreq[:]); n != 299 || err != nil {
		f.Fatal()
	}
	f.Add(invalid_rreq[:])

	f.Fuzz(func(t *testing.T, bytes []byte) {
		assert.NotPanics(t, func() {
			network_layer.DecodeRREQ(bytes)
		})
	})
}
