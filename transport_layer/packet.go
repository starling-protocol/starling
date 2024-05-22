package transport_layer

import "errors"

type PacketType int64

const (
	DATA PacketType = 0x01
	ACK  PacketType = 0x02
)

type Packet interface {
	EncodePacket() []byte
	PacketType() PacketType
}

func (transport *TransportLayer) decodeTransportPacket(data []byte) (Packet, error) {
	transport.logf("decode:packet 'Decoding packet of %d bytes'", len(data))

	packet_type := PacketType(data[0])

	switch packet_type {
	case DATA:
		return DecodeDataPacket(data)
	case ACK:
		return DecodeACKPacket(data)
	default:
		return nil, errors.New("invalid transport packet type")
	}
}
