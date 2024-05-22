package packet_layer

import (
	"container/list"
	"errors"
	"fmt"
)

type PacketEncoder struct {
	packets       *list.List
	workingPacket []byte
	cursor        int
	packetSize    int
}

func NewPacketEncoder(packetSize int) *PacketEncoder {
	if packetSize < 3 {
		panic("NewPacketEncoder: packetSize should be at least 3")
	}

	if packetSize >= 1<<14 {
		panic(fmt.Sprintf("NewPacketEncoder: packetSize should be at most %d", 1<<13))
	}

	return &PacketEncoder{
		packets:       list.New(),
		workingPacket: make([]byte, packetSize),
		cursor:        0,
		packetSize:    packetSize,
	}
}

func (encoder *PacketEncoder) PacketSize() int {
	return encoder.packetSize
}

// PopPacket removes and returns the first packet in encoder
func (encoder *PacketEncoder) PopPacket() []byte {
	if encoder.packets.Len() == 0 {
		if encoder.cursor > 0 {
			packet := encoder.workingPacket[:encoder.cursor]
			encoder.workingPacket = make([]byte, encoder.packetSize)
			encoder.cursor = 0
			return packet[:]
		} else {
			return []byte{}
		}
	} else {
		return encoder.packets.Remove(encoder.packets.Front()).([]byte)
	}
}

func (encoder *PacketEncoder) PacketCount() int {
	if encoder.cursor > 0 {
		return encoder.packets.Len() + 1
	} else {
		return encoder.packets.Len()
	}
}

func (encoder *PacketEncoder) writeNextPacket() {
	encoder.packets.PushBack(encoder.workingPacket[0:encoder.cursor])
	encoder.workingPacket = make([]byte, encoder.packetSize)
	encoder.cursor = 0
}

// EncodeMessage encodes the given message to the last packet in the encoder
// potentially creating a new packet if it does not fit.
func (encoder *PacketEncoder) EncodeMessage(message []byte) error {
	copyMessage := func(message []byte, flags packetFlags) error {
		header := newPacketHeader(len(message), flags)
		headerBytes := header.toBytes()
		encoder.workingPacket[encoder.cursor] = headerBytes[0]
		encoder.workingPacket[encoder.cursor+1] = headerBytes[1]

		if len(message) > len(encoder.workingPacket[encoder.cursor+2:]) {
			return errors.New("message does not fit in packet")
		}

		// body
		copy(encoder.workingPacket[encoder.cursor+2:], message)
		encoder.cursor += len(message) + 2

		return nil
	}

	// edge case with a single byte left
	if encoder.cursor >= encoder.packetSize-2 {
		// finish this packet and start on next
		encoder.writeNextPacket()
	}

	remaining := []byte{}

	if len(message) > (encoder.packetSize - encoder.cursor - 2) {
		flags := newPacketFlags(true)

		// break up
		startReadCount := encoder.packetSize - encoder.cursor - 2
		if err := copyMessage(message[0:startReadCount], flags); err != nil {
			return err
		}
		encoder.writeNextPacket()
		remaining = message[startReadCount:]
	} else {
		if err := copyMessage(message, newPacketFlags(false)); err != nil {
			return err
		}
	}

	for len(remaining) > 0 {
		if len(remaining) > (encoder.packetSize - encoder.cursor - 2) {
			flags := newPacketFlags(true)

			// break up
			if err := copyMessage(remaining[0:encoder.packetSize-encoder.cursor-2], flags); err != nil {
				return err
			}
			encoder.writeNextPacket()
			remaining = remaining[encoder.packetSize-2:]
		} else {
			if err := copyMessage(remaining, newPacketFlags(false)); err != nil {
				return err
			}
			remaining = []byte{}
		}
	}

	return nil
}
