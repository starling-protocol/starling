package packet_layer_test

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/starling-protocol/starling/packet_layer"

	"github.com/stretchr/testify/assert"
)

func TestEncodeSimpleMessage(t *testing.T) {
	msg := "hello"

	pkg := [7]byte{}
	pkg[0] = 0b10000000
	pkg[1] = byte(len(msg))
	copy(pkg[2:], msg)

	encoder := packet_layer.NewPacketEncoder(514)

	encoder.EncodeMessage([]byte(msg))

	assert.Equal(t, 1, encoder.PacketCount())
	assert.Equal(t, pkg[:], encoder.PopPacket())
}

func TestEncodeTwoMessagesOnePacket(t *testing.T) {
	const packetSize int = 514
	msgs := []string{"Hi Bob", "Hi Charlie"}

	pkg := [20]byte{}
	offset := 0

	encoder := packet_layer.NewPacketEncoder(packetSize)

	for _, msg := range msgs {
		pkg[offset+0] = 0b10000000
		pkg[offset+1] = byte(len(msg))
		copy(pkg[offset+2:], msg)
		offset += len(msg) + 2

		encoder.EncodeMessage([]byte(msg))
	}

	assert.Equal(t, 1, encoder.PacketCount())
	assert.Equal(t, pkg[:], encoder.PopPacket())
}

func longMessagePackets() [][514]byte {
	const packetSize int = 514
	const fstPkgData = 514 - 2

	msg := []byte(strings.Repeat("A", 600))

	pkgs := [][packetSize]byte{}

	// first packet
	pkg := [packetSize]byte{}
	pkg[0] = 0b11000000 | byte(fstPkgData>>8)
	pkg[1] = byte(fstPkgData & 0xff)
	copy(pkg[2:], msg)
	pkgs = append(pkgs, pkg)

	// second packet
	pkg = [packetSize]byte{}
	pkg[0] = 0b10000000
	pkg[1] = byte(len(msg) - fstPkgData)
	copy(pkg[2:], msg[fstPkgData:])
	pkgs = append(pkgs, pkg)

	return pkgs
}

func TestEncodeSingleMessageTwoPackets(t *testing.T) {
	const packetSize int = 514
	msg := []byte(strings.Repeat("A", 600))
	pkgs := longMessagePackets()

	bundle := packet_layer.NewPacketEncoder(packetSize)
	bundle.EncodeMessage(msg)

	assert.Equal(t, 2, bundle.PacketCount())
	assert.Equal(t, pkgs[0][:], bundle.PopPacket())
	assert.Equal(t, pkgs[1][:604-packetSize], bundle.PopPacket())
	assert.Equal(t, 0, bundle.PacketCount())
}

func FuzzPacketBundle(f *testing.F) {
	type Testcase struct {
		packetSize int
		message    []byte
	}

	testcases := []Testcase{
		{
			packetSize: 514,
			message:    []byte("Hi alice"),
		},
		{
			packetSize: 514,
			message:    []byte(strings.Repeat("A", 513)),
		},
		{
			packetSize: 514,
			message:    []byte(strings.Repeat("B", 514)),
		},
		{
			packetSize: 514,
			message:    []byte(strings.Repeat("C", 515)),
		},
		{
			packetSize: 514,
			message:    []byte(strings.Repeat("D", 600)),
		},
		{
			packetSize: 514,
			message:    []byte(strings.Repeat("D", 1200)),
		},
		{
			packetSize: 3,
			message:    []byte("Hello world!"),
		},
	}

	for _, tc := range testcases {
		f.Add(tc.packetSize, tc.message)
	}

	r := rand.New(rand.NewSource(1234))

	for i := 0; i < 3; i++ {
		packetSize := r.Intn(400) + 1
		length := r.Intn(1200)
		msg := make([]byte, length)
		for j := 0; j < length; j++ {
			msg[j] = byte(r.Intn(256))
		}

		f.Add(packetSize, msg)
	}

	f.Fuzz(func(t *testing.T, packetSize int, message []byte) {
		if packetSize < 3 {
			return
		}

		encoder := packet_layer.NewPacketEncoder(packetSize)
		encoder.EncodeMessage(message)

		decoder := packet_layer.NewPacketDecoder()
		for encoder.PacketCount() > 0 {
			decoder.AppendPacket(encoder.PopPacket())
		}

		hasMsg, err := decoder.HasMessage()
		assert.NoError(t, err)
		assert.True(t, hasMsg)

		decodedMsg, err := decoder.ReadMessage()
		assert.NoError(t, err)
		assert.Equal(t, message, decodedMsg)

		hasMsg, err = decoder.HasMessage()
		assert.NoError(t, err)
		assert.False(t, hasMsg)
	})
}
