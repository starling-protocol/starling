package network_layer_test

import (
	"crypto/ecdh"
	"math/rand"
	"testing"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/network_layer"
	"github.com/starling-protocol/starling/testutils"

	"github.com/stretchr/testify/assert"
)

func newRREP(t testing.TB, random *rand.Rand, reqID network_layer.RequestID, sessID device.SessionID, ownEphemeralPrivateKey *ecdh.PrivateKey, payload []byte) *network_layer.RREPPacket {
	dev := testutils.NewDeviceMock(t, random)
	network := network_layer.NewNetworkLayer(dev, nil, *device.DefaultProtocolOptions())

	secret := [32]byte{}
	if n, err := random.Read(secret[:]); n != 32 || err != nil {
		t.Fatal("read secret failed")
	}

	contact := dev.Contacts.DebugLink(secret[:])

	otherEphemeralPrivateKey, err := ecdh.X25519().GenerateKey(dev.CryptoRand())
	assert.NoError(t, err)

	sessionSecret, err := network_layer.SessionSecret(dev.Contacts, contact, ownEphemeralPrivateKey.Bytes(), otherEphemeralPrivateKey.PublicKey().Bytes())
	assert.NoError(t, err)

	rrep, err := network.NewRREP(reqID, sessID, sessionSecret, *ownEphemeralPrivateKey.PublicKey(), payload)
	assert.NoError(t, err)

	return rrep
}

func FuzzCodingRREP(f *testing.F) {

	f.Add(int64(1234), 1, 2, []byte{})
	f.Add(int64(1234), 1, 2, []byte("payload"))

	f.Fuzz(func(t *testing.T, seed int64, _reqID int, _sessID int, payload []byte) {
		random := rand.New(rand.NewSource(seed))
		reqID := network_layer.RequestID(_reqID)
		sessID := device.SessionID(_sessID)
		ephemeralPrivate, err := ecdh.X25519().GenerateKey(random)
		assert.NoError(t, err)

		rrep := newRREP(t, random, reqID, sessID, ephemeralPrivate, payload)

		assert.Equal(t, reqID, rrep.RequestID)
		assert.Equal(t, sessID, rrep.SessionID)
		assert.Equal(t, *ephemeralPrivate.PublicKey(), rrep.EphemeralKey)
		assert.Len(t, rrep.Cipher, 16+len(payload))
		assert.Len(t, rrep.Nonce, 12)

		encoded := rrep.EncodePacket()
		assert.Len(t, encoded, 65+len(payload)+16)

		decoded, err := network_layer.DecodeRREP(encoded)
		assert.NoError(t, err, "failed to decode RREP packet")

		assert.Equal(t, rrep, decoded)
	})

}

func FuzzDecodingRREP(f *testing.F) {
	random := rand.New(rand.NewSource(1234))

	ephemeralPrivate1, err := ecdh.X25519().GenerateKey(random)
	assert.NoError(f, err)

	rrep := newRREP(f, random, network_layer.RequestID(456), device.SessionID(654), ephemeralPrivate1, []byte{})
	f.Add(rrep.EncodePacket())

	ephemeralPrivate2, err := ecdh.X25519().GenerateKey(random)
	assert.NoError(f, err)

	rrep = newRREP(f, random, network_layer.RequestID(123), device.SessionID(321), ephemeralPrivate2, []byte("payload"))
	f.Add(rrep.EncodePacket())

	invalid_rrep := [50]byte{}
	if n, err := random.Read(invalid_rrep[:]); n != 50 || err != nil {
		f.Fatal()
	}
	f.Add(invalid_rrep[:])

	f.Fuzz(func(t *testing.T, bytes []byte) {
		assert.NotPanics(t, func() {
			network_layer.DecodeRREP(bytes)
		})
	})
}
