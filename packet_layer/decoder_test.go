package packet_layer_test

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/starling-protocol/starling/packet_layer"

	"github.com/stretchr/testify/assert"
)

func TestDecodeSimpleMessage(t *testing.T) {
	const packetSize int = 514
	msg := "hello"

	pkg := [packetSize]byte{}
	pkg[0] = 0b10000000
	pkg[1] = byte(len(msg))
	copy(pkg[2:], msg)

	decoder := packet_layer.NewPacketDecoder()
	decoder.AppendPacket(pkg[:])

	assert.Equal(t, 1, decoder.PacketCount())

	decodedMsg, err := decoder.ReadMessage()
	assert.NoError(t, err)
	assert.Equal(t, []byte(msg), decodedMsg)
}

func TestDecodeTwoMessagesOnePacket(t *testing.T) {
	const packetSize int = 514
	msgs := []string{"Hi Bob", "Hi Charlie"}

	pkg := [packetSize]byte{}
	offset := 0

	decoder := packet_layer.NewPacketDecoder()

	for _, msg := range msgs {
		pkg[offset+0] = 0b10000000
		pkg[offset+1] = byte(len(msg))
		copy(pkg[offset+2:], msg)
		offset += len(msg) + 2
	}
	decoder.AppendPacket(pkg[:])

	hasMsg, err := decoder.HasMessage()
	assert.NoError(t, err)
	assert.True(t, hasMsg)

	for i := 0; i < 2; i++ {
		decodedMsg, err := decoder.ReadMessage()
		assert.NoError(t, err)
		assert.Equal(t, []byte(msgs[i]), decodedMsg)
	}

	hasMsg, err = decoder.HasMessage()
	assert.NoError(t, err)
	assert.False(t, hasMsg)
}

func TestDecodeSingleMessageTwoPackets(t *testing.T) {
	msg := []byte(strings.Repeat("A", 600))
	pkgs := longMessagePackets()

	decoder := packet_layer.NewPacketDecoder()
	decoder.AppendPacket(pkgs[0][:])
	decoder.AppendPacket(pkgs[1][:])

	assert.Equal(t, 2, decoder.PacketCount())

	hasMsg, err := decoder.HasMessage()
	assert.NoError(t, err)
	assert.True(t, hasMsg)

	decodedMsg, err := decoder.ReadMessage()
	assert.NoError(t, err)
	assert.Equal(t, []byte(msg), decodedMsg)

	hasMsg, err = decoder.HasMessage()
	assert.NoError(t, err)
	assert.False(t, hasMsg)
}

func TestDecodePartialMessage(t *testing.T) {
	decoder := packet_layer.NewPacketDecoder()

	// Append only first package (of two)
	pkgs := longMessagePackets()
	decoder.AppendPacket(pkgs[0][:])

	hasMsg, err := decoder.HasMessage()
	assert.NoError(t, err)
	assert.False(t, hasMsg)
}

func FuzzDecodeRandomBytes(f *testing.F) {
	r := rand.New(rand.NewSource(1234))

	for i := 0; i < 5; i++ {
		length := r.Intn(1200)
		bytes := make([]byte, length)
		for j := 0; j < length; j++ {
			bytes[j] = byte(r.Intn(256))
		}

		f.Add(bytes)
	}

	f.Fuzz(func(t *testing.T, bytes []byte) {
		decoder := packet_layer.NewPacketDecoder()
		decoder.AppendPacket(bytes)

		hasMsg, err := decoder.HasMessage()
		for hasMsg || err != nil {
			if err == nil {
				decoder.ReadMessage()
			}
			hasMsg, err = decoder.HasMessage()
		}
	})
}
