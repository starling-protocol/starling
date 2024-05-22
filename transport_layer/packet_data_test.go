package transport_layer_test

import (
	"math/rand"
	"testing"

	"github.com/starling-protocol/starling/transport_layer"

	"github.com/stretchr/testify/assert"
)

func FuzzCodingDataPacket(f *testing.F) {
	f.Add(uint32(1), []byte("hello"))
	f.Add(uint32(9999), []byte{0, 1, 2, 3})

	f.Fuzz(func(t *testing.T, _seqID uint32, data []byte) {
		seqID := transport_layer.SequenceID(_seqID)

		packet := transport_layer.NewDATAPacket(seqID, data)

		encoded := packet.EncodePacket()
		decoded, err := transport_layer.DecodeDataPacket(encoded)
		assert.NoError(t, err)

		assert.EqualValues(t, packet, decoded)
	})

}

func FuzzDecodingDataPacket(f *testing.F) {
	random := rand.New(rand.NewSource(1234))

	packet := transport_layer.NewDATAPacket(1, []byte("hello"))
	f.Add(packet.EncodePacket())

	invalid_packet := [45]byte{}
	if n, err := random.Read(invalid_packet[:]); n != 45 || err != nil {
		f.Fatal()
	}
	f.Add(invalid_packet[:])

	f.Fuzz(func(t *testing.T, bytes []byte) {
		assert.NotPanics(t, func() {
			transport_layer.DecodeDataPacket(bytes)
		})
	})
}
