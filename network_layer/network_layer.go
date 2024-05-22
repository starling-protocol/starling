package network_layer

import (
	"fmt"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/packet_layer"
	"github.com/starling-protocol/starling/utils"
)

type NetworkLayer struct {
	dev          device.Device
	events       NetworkLayerEvents
	options      device.ProtocolOptions
	packetLayer  *packet_layer.PacketLayer
	requestTable RequestTable
	sessionTable SessionTable
}

type NetworkLayerEvents interface {
	SessionEstablished(session device.SessionID, contact device.ContactID, address device.DeviceAddress, payload []byte, isInitiator bool)
	SessionBroken(session device.SessionID)
	ReplyPayload(session device.SessionID, contact device.ContactID) []byte
}

func NewNetworkLayer(dev device.Device, events NetworkLayerEvents, options device.ProtocolOptions) *NetworkLayer {
	layer := &NetworkLayer{
		dev:          dev,
		events:       events,
		options:      options,
		packetLayer:  packet_layer.NewLinkLayer(dev, options),
		requestTable: make(RequestTable),
		sessionTable: make(SessionTable),
	}
	return layer
}

func (network *NetworkLayer) log(body ...any) {
	network.dev.Log(fmt.Sprintf("network:%s", fmt.Sprint(body...)))
}

func (network *NetworkLayer) logf(msg string, args ...any) {
	network.log(fmt.Sprintf(msg, args...))
}

func (network *NetworkLayer) OnConnection(address device.DeviceAddress) {
	network.packetLayer.OnConnection(address)

	if !network.options.DisableAutoRREQOnConnection {
		network.SendRouteRequest(address, 1)
	}
}

func (network *NetworkLayer) OnDisconnection(address device.DeviceAddress) {
	network.packetLayer.OnDisconnection(address)
	network.handleDisconnect(address)
}

func (network *NetworkLayer) ReceivePacket(sender device.DeviceAddress, packet []byte) []SessionMessage {
	packets := network.packetLayer.ReceivePacket(sender, packet)

	sessionData := []SessionMessage{}
	for _, packet := range packets {
		packet, err := DecodeRoutingPacket(packet)
		if err != nil {
			network.logf("packet:receive:error '%v'", err)
			continue
		}

		content := network.handlePacket(sender, packet)
		if content != nil {
			sessionData = append(sessionData, *content)
		}
	}

	return sessionData
}

func (network *NetworkLayer) handlePacket(sender device.DeviceAddress, packet Packet) *SessionMessage {
	switch packet.PacketType() {
	case RREQ:
		rreq := packet.(*RREQPacket)
		network.handleRouteRequest(*rreq, sender)
	case RREP:
		rrep := packet.(*RREPPacket)
		network.handleRouteReply(*rrep, sender)
	case SESS:
		data := packet.(*SESSPacket)
		return network.handleSESSPacket(data, sender)
	case RERR:
		rerr := packet.(*RERRPacket)
		network.handleRouteErrorPacket(*rerr, sender)
	default:
		network.logf("packet:handle:error 'unknown network packet type %v'", packet.PacketType())
	}

	return nil
}

func (network *NetworkLayer) DeleteContact(contact device.ContactID) {
	// delete(network.contacts, contact)
	network.dev.ContactsContainer().DeleteContact(contact)

	for _, sessionID := range utils.ShuffleMapKeys(network.dev.Rand(), network.sessionTable) {
		session := network.sessionTable[sessionID]
		if session.Contact != nil && *session.Contact == contact {
			network.SessionBroken(sessionID, nil)
			delete(network.requestTable, session.RequestID)
			delete(network.sessionTable, session.SessionID)

		}
	}

	totalContacts := len(network.dev.ContactsContainer().AllGroups()) + len(network.dev.ContactsContainer().AllLinks())
	network.logf("delete_contact:deleted 'Deleted contact, %d total contacts'", totalContacts)
}
