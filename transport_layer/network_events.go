package transport_layer

import (
	"github.com/starling-protocol/starling/device"
)

type networkEvents struct {
	transport *TransportLayer
}

// SessionBroken implements network_layer.NetworkLayerEvents.
func (n *networkEvents) SessionBroken(session device.SessionID) {
	n.transport.events.SessionBroken(session)

	awaitingAcks := 0
	state, found := n.transport.sessionStates[session]
	if found {
		awaitingAcks = len(state.sender.awaitingACKs)
	}
	if len(n.transport.outbox)+awaitingAcks > 0 {
		n.transport.networkLayer.BroadcastRouteRequest()
	}
}

// SessionEstablished implements network_layer.NetworkLayerEvents.
func (n *networkEvents) SessionEstablished(session device.SessionID, contact device.ContactID, address device.DeviceAddress, payload []byte, isInitiator bool) {
	var applicationPayload []byte = nil

	if len(payload) > 0 {
		payloadMessages := n.transport.handlePacket(session, payload)
		if len(payloadMessages) > 0 {
			if len(payloadMessages) != 1 {
				n.transport.logf("event:session_establish:error 'received multiple packets which should be impossible here'")
			}
			applicationPayload = payloadMessages[0].Data
		}
	}

	n.transport.events.SessionEstablished(session, contact, address, applicationPayload, isInitiator)
}

// ReplyPayload implements network_layer.NetworkLayerEvents.
func (n *networkEvents) ReplyPayload(sessionID device.SessionID, contact device.ContactID) []byte {
	data := n.transport.events.ReplyPayload(sessionID, contact)

	dataPacket, _, err := n.transport.newMessage(sessionID, data)
	if err != nil {
		n.transport.logf("reply_payload:error '%v'", err)
		return nil
	}

	return dataPacket.EncodePacket()
}
