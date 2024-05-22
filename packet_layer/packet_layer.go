package packet_layer

import (
	"encoding/base64"
	"fmt"
	"math"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/utils"
)

type connection struct {
	encoder *PacketEncoder
	decoder *PacketDecoder
}

func newConnection(packetSize int) *connection {
	return &connection{
		encoder: NewPacketEncoder(packetSize),
		decoder: NewPacketDecoder(),
	}
}

type PacketLayer struct {
	dev         device.Device
	options     device.ProtocolOptions
	connections map[device.DeviceAddress]*connection
}

func (link *PacketLayer) log(body ...any) {
	link.dev.Log(fmt.Sprintf("link:%s", fmt.Sprint(body...)))
}

func (link *PacketLayer) logf(msg string, args ...any) {
	link.log(fmt.Sprintf(msg, args...))
}

func NewLinkLayer(dev device.Device, options device.ProtocolOptions) *PacketLayer {
	return &PacketLayer{
		dev:         dev,
		options:     options,
		connections: make(map[device.DeviceAddress]*connection),
	}
}

func (link *PacketLayer) OnConnection(address device.DeviceAddress) {
	packetSize, err := link.dev.MaxPacketSize(address)
	if err != nil {
		link.logf("OnConnect: failed to get MaxPacketSize: %v", err)
		return
	}

	link.connections[address] = newConnection(packetSize)
}

func (link *PacketLayer) OnDisconnection(address device.DeviceAddress) {
	delete(link.connections, address)
}

func (link *PacketLayer) ReceivePacket(sender device.DeviceAddress, packet []byte) [][]byte {
	conn, found := link.connections[sender]
	if !found {
		link.log("receive:decode:error 'connection was not found'")
		return [][]byte{}
	}

	if err := conn.decoder.AppendPacket(packet); err != nil {
		link.logf("receive:decode:error 'failed to append packet: %v'", err)
		return [][]byte{}
	}

	messages := [][]byte{}

	for {
		hasMsg, err := conn.decoder.HasMessage()
		if err != nil {
			link.logf("receive:decode:error 'failed to decode packet: %v'", err)
			continue
		}
		if !hasMsg {
			break
		}

		msg, err := conn.decoder.ReadMessage()
		if err != nil {
			link.logf("receive:decode:error 'failed to decode packet: %v'", err)
			continue
		}

		messages = append(messages, msg)
	}

	if len(messages) > 0 {
		link.logf("receive:decode:%s 'decoded %d message(s)'", sender, len(messages))
	}

	return messages
}

func (link *PacketLayer) BroadcastBytes(data []byte) {
	link.logf("broadcast 'broadcasting packet to %d peer(s)'", len(link.connections))
	for _, address := range utils.ShuffleMapKeys(link.dev.Rand(), link.connections) {
		link.SendBytes(address, data)
	}
}

// Broadcasts bytes to some of the neighbours, except for exceptAddress
func (link *PacketLayer) BroadcastBytesExcept(data []byte, exceptAddress device.DeviceAddress) {
	switch link.options.RREQBroadcastStrategy {
	case device.BroadcastLogFunc:
		count := 0
		connectionCount := len(link.connections) - 1
		for _, address := range utils.ShuffleMapKeys(link.dev.Rand(), link.connections) {
			if address != exceptAddress {
				if count < min(connectionCount, int(math.Log2(float64(connectionCount))+1)) {
					link.SendBytes(address, data)
				}
				count++
			}
		}
		link.logf("broadcast 'broadcasting packet to %d peer(s)'", count)
	case device.BroadcastAll:
		link.logf("broadcast 'broadcasting packet to %d peer(s)'", len(link.connections)-1)
		for _, address := range utils.ShuffleMapKeys(link.dev.Rand(), link.connections) {
			if address != exceptAddress {
				link.SendBytes(address, data)
			}
		}
	case device.BroadcastTwo:
		count := 0
		adresses := utils.ShuffleMapKeys(link.dev.Rand(), link.connections)
		for i := range 2 {
			if len(adresses) > i {
				link.SendBytes(adresses[i], data)
				count++
			}
		}
		link.logf("broadcast 'broadcasting packet to %d peer(s)'", count)
	default:
		panic("invalid protocol option")
	}
}

func (link *PacketLayer) SendBytes(address device.DeviceAddress, data []byte) bool {
	packetSize, err := link.dev.MaxPacketSize(address)
	if err != nil {
		link.logf("send:error 'failed to get MaxPacketSize: %v'", err)
		return false
	}

	conn, found := link.connections[address]
	if !found {
		link.log("send:error 'connection was not found'")
		return false
	}

	if packetSize != conn.encoder.PacketSize() {
		conn.encoder = NewPacketEncoder(packetSize)
	}

	if err := conn.encoder.EncodeMessage(data); err != nil {
		link.log("send:error 'failed to encode message'")
		return false
	}

	link.logf("send:packets:%s:%d:%s", address, conn.encoder.PacketCount(), base64.StdEncoding.EncodeToString(data))
	for conn.encoder.PacketCount() > 0 {
		packetBytes := conn.encoder.PopPacket()
		link.dev.SendPacket(address, packetBytes)
	}
	return true
}
