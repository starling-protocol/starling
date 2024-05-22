package network_layer

import (
	"errors"
)

func DecodeRoutingPacket(data []byte) (Packet, error) {
	var packet_type = PacketType(data[0])

	switch packet_type {
	case RREQ:
		return DecodeRREQ(data)
	case RREP:
		return DecodeRREP(data)
	case RERR:
		return DecodeRERR(data)
	case SESS:
		return DecodeSESS(data)
	default:
		return nil, errors.New("invalid network packet type")
	}
}
