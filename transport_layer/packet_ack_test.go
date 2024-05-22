package transport_layer_test

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/starling-protocol/starling/transport_layer"

	"github.com/stretchr/testify/assert"
)

func FuzzCodingAckPacket(f *testing.F) {
	missingAcks := []byte{}
	missingAcks = binary.BigEndian.AppendUint32(missingAcks, 345)
	missingAcks = binary.BigEndian.AppendUint32(missingAcks, 678)
	f.Add(uint32(1000), missingAcks)

	f.Fuzz(func(t *testing.T, latestSeqID uint32, _missingSeqIDs []byte) {
		missingSeqIDs := []transport_layer.SequenceID{}
		for i := 0; i < len(_missingSeqIDs)/4; i++ {
			seq := binary.BigEndian.Uint32(_missingSeqIDs[i*4:])
			missingSeqIDs = append(missingSeqIDs, transport_layer.SequenceID(seq))
		}

		packet := transport_layer.NewACKPacket(transport_layer.SequenceID(latestSeqID), missingSeqIDs)

		encoded := packet.EncodePacket()
		decoded, err := transport_layer.DecodeACKPacket(encoded)
		assert.NoError(t, err)

		assert.EqualValues(t, packet, decoded)
	})
}

func FuzzDecodingAckPacket(f *testing.F) {
	random := rand.New(rand.NewSource(1234))

	packet := transport_layer.NewACKPacket(transport_layer.SequenceID(500), []transport_layer.SequenceID{40292, 3843})
	f.Add(packet.EncodePacket())

	invalid_packet := [45]byte{}
	if n, err := random.Read(invalid_packet[:]); n != 45 || err != nil {
		f.Fatal()
	}
	f.Add(invalid_packet[:])

	f.Fuzz(func(t *testing.T, bytes []byte) {
		assert.NotPanics(t, func() {
			transport_layer.DecodeACKPacket(bytes)
		})
	})
}
