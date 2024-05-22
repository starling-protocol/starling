package packet_layer

import (
	"container/list"
	"errors"
	"fmt"
)

type PacketDecoder struct {
	packets *list.List
	cursor  int
}

func NewPacketDecoder() *PacketDecoder {
	return &PacketDecoder{
		packets: list.New(),
		cursor:  0,
	}
}

func (decoder *PacketDecoder) PacketCount() int {
	return decoder.packets.Len()
}

// frontPacket returns a copy of the first packet in the decoder
func (decoder *PacketDecoder) frontPacket() []byte {
	return decoder.packets.Front().Value.([]byte)
}

// AppendPacket adds a packet to the end of the decoder
func (decoder *PacketDecoder) AppendPacket(packet []byte) error {
	if len(packet) >= 1<<14 {
		return fmt.Errorf("PacketDecoder.AppendPacket: packetSize should be at most %d", 1<<13)
	}

	newPacket := make([]byte, len(packet))
	copy(newPacket[:], packet)
	decoder.packets.PushBack(newPacket)

	return nil
}

func (decoder *PacketDecoder) readNextPacket() {
	decoder.packets.Remove(decoder.packets.Front())
	decoder.cursor = 0
}

func (decoder *PacketDecoder) skipEmptyPackets() error {
	for {
		if decoder.packets.Len() == 0 {
			break
		}
		packet := decoder.frontPacket()[decoder.cursor:]
		if len(packet) < 2 {
			decoder.readNextPacket()
			break
		}

		header, err := packetHeaderFromBytes(packet)
		if err != nil {
			return err
		}

		if !header.flags.NonEmpty {
			decoder.readNextPacket()
		} else {
			break
		}
	}

	return nil
}

// HasMessage returns true if there are messages to be decoded
func (decoder *PacketDecoder) HasMessage() (bool, error) {
	if err := decoder.skipEmptyPackets(); err != nil {
		decoder.readNextPacket()
		return false, err
	}

	if decoder.packets.Len() == 0 {
		return false, nil
	}

	packetElm := decoder.packets.Front()
	cursor := decoder.cursor

	for packetElm != nil {
		packet := packetElm.Value.([]byte)
		header, err := packetHeaderFromBytes(packet[cursor:])
		if err != nil {
			return false, err
		}

		if !header.flags.Continuation {
			return true, nil
		}

		cursor += header.size + 2
		if cursor >= len(packet)-3 {
			packetElm = packetElm.Next()
			cursor = 0
		}
	}

	return false, nil
}

// ReadMessage decodes and removes the first message in the decoder
func (decoder *PacketDecoder) ReadMessage() ([]byte, error) {
	hasMsg, err := decoder.HasMessage()
	if err != nil {
		return nil, err
	}

	if !hasMsg {
		return nil, errors.New("no message to read")
	}

	msg := []byte{}
	continuation := true

	for decoder.packets.Len() > 0 && continuation {
		packet := decoder.frontPacket()[decoder.cursor:]
		header, err := packetHeaderFromBytes(packet)
		if err != nil {
			decoder.readNextPacket()
			return nil, err
		}

		if header.size > len(packet)-2 {
			decoder.readNextPacket()
			return nil, errors.New("corrupt packet: header size longer than packet")
		}

		msg = append(msg, packet[2:header.size+2]...)

		continuation = header.flags.Continuation
		decoder.cursor += header.size + 2
		if decoder.cursor >= len(decoder.frontPacket()) {
			decoder.readNextPacket()
		}
	}

	if continuation {
		panic("unreachable: should have been caught by decoder.HasMessage()")
	}

	return msg, nil
}
