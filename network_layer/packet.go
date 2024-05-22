package network_layer

import "github.com/starling-protocol/starling/device"

type PacketType int64

const (
	RREQ PacketType = 0x01
	RREP PacketType = 0x02
	SESS PacketType = 0x03
	RERR PacketType = 0x04
)

type Packet interface {
	EncodePacket() []byte
	PacketType() PacketType
}

func (network *NetworkLayer) BroadcastPacket(packet Packet) {
	network.log("packet:broadcast")
	network.packetLayer.BroadcastBytes(packet.EncodePacket())
}

func (network *NetworkLayer) BroadcastPacketExcept(packet Packet, except device.DeviceAddress) {
	network.logf("packet:broadcast:except:%s", except)
	network.packetLayer.BroadcastBytesExcept(packet.EncodePacket(), except)
}
