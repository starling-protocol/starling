package transport_layer

import (
	"errors"
	"fmt"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/network_layer"
	"github.com/starling-protocol/starling/utils"
)

type TransportLayer struct {
	dev           device.Device
	events        TransportEvents
	options       device.ProtocolOptions
	networkLayer  *network_layer.NetworkLayer
	outbox        []outboxMessage
	sessionStates map[device.SessionID]*SessionState
}

type TransportEvents interface {
	SessionEstablished(session device.SessionID, contact device.ContactID, address device.DeviceAddress, payload []byte, isInitiator bool)
	SessionBroken(session device.SessionID)
	ReplyPayload(session device.SessionID, contact device.ContactID) []byte
	MessageDelivered(messageID device.MessageID)
}

//TODO: Discuss. How can a node which is currently in communication with a contact distinguish packets sent by the contact from its own packets?
// An intermediate node could just route it backwards

func NewTransportLayer(dev device.Device, events TransportEvents, options device.ProtocolOptions) *TransportLayer {
	transport := TransportLayer{
		dev:           dev,
		events:        events,
		options:       options,
		networkLayer:  nil,
		outbox:        []outboxMessage{},
		sessionStates: map[device.SessionID]*SessionState{},
	}

	transport.networkLayer = network_layer.NewNetworkLayer(dev, &networkEvents{transport: &transport}, options)

	return &transport
}

func (transport *TransportLayer) SessionState(sessionID device.SessionID) *SessionState {
	state, found := transport.sessionStates[sessionID]
	if !found {
		state = NewSessionState(sessionID)
		transport.sessionStates[sessionID] = state
	}

	return state
}

func (transport *TransportLayer) OnConnection(address device.DeviceAddress) {
	transport.networkLayer.OnConnection(address)
}

func (transport *TransportLayer) OnDisconnection(address device.DeviceAddress) {
	transport.handleDisconnect(address)
	transport.networkLayer.OnDisconnection(address)
}

func (transport *TransportLayer) BroadcastRouteRequest() {
	transport.networkLayer.BroadcastRouteRequest()
}

func (transport *TransportLayer) SessionContact(sessionID device.SessionID) (*device.ContactID, bool) {
	session, found := transport.networkLayer.GetSession(sessionID)
	if !found || session.Contact == nil {
		return nil, false
	}

	return session.Contact, true
}

func (transport *TransportLayer) AllSessions(contact device.ContactID) []device.SessionID {
	return transport.networkLayer.AllSessions(contact)
}

// func (transport *TransportLayer) ContactSecret(contact device.ContactID) (device.SharedSecret, bool) {
// 	return transport.networkLayer.ContactSecret(contact)
// }

func (transport *TransportLayer) handleDisconnect(address device.DeviceAddress) {
	for _, sessID := range utils.ShuffleMapKeys(transport.dev.Rand(), transport.sessionStates) {
		session, found := transport.networkLayer.GetSession(sessID)

		if !found {
			transport.logf("handle_disconnect:clear_state:%d:%s:session_not_found", sessID, address)
			delete(transport.sessionStates, sessID)
			continue
		}

		if (session.SourceNeighbour != nil && *session.SourceNeighbour == address) ||
			(session.TargetNeighbour != nil && *session.TargetNeighbour == address) {
			transport.logf("handle_disconnect:clear_state:%d:%s", sessID, address)
			delete(transport.sessionStates, sessID)
			continue
		}
	}
}

type TransportMessage struct {
	Contact device.ContactID
	Session device.SessionID
	Data    []byte
}

func (transport *TransportLayer) ReceivePacket(address device.DeviceAddress, packet []byte) []TransportMessage {
	messages := []TransportMessage{}

	packets := transport.networkLayer.ReceivePacket(address, packet)
	for _, net_packet := range packets {
		transportMessages := transport.handlePacket(net_packet.SessionID(), net_packet.Data())
		if len(transportMessages) > 0 {
			messages = append(messages, transportMessages...)
		}
	}

	return messages
}

func (transport *TransportLayer) handlePacket(sessionID device.SessionID, data []byte) []TransportMessage {
	packet, err := transport.decodeTransportPacket(data)
	if err != nil {
		transport.logf("packet:handle:decode:error '%v'", err)
		return nil
	}

	switch packet.PacketType() {
	case DATA:
		dataPacket := packet.(*DATAPacket)
		return transport.handleDataPacket(sessionID, dataPacket)
	case ACK:
		ACKPacket := packet.(*ACKPacket)
		transport.handleACKPacket(sessionID, ACKPacket)
		return nil
	default:
		transport.logf("packet:handle:error 'unknown transport packet type %v'", packet.PacketType())
		return nil
	}
}

func (transport *TransportLayer) log(body ...any) {
	transport.dev.Log(fmt.Sprintf("transport:%s", fmt.Sprint(body...)))
}

func (transport *TransportLayer) logf(msg string, args ...any) {
	transport.log(fmt.Sprintf(msg, args...))
}

type outboxMessage struct {
	session   device.SessionID
	messageID device.MessageID
	body      []byte
}

func newOutboxMessage(session device.SessionID, messageID device.MessageID, body []byte) outboxMessage {
	return outboxMessage{
		session:   session,
		messageID: messageID,
		body:      body,
	}
}

// Creates a new message and registers it for delivery, the caller is responsible for sending it.
func (transport *TransportLayer) newMessage(sessionID device.SessionID, message []byte) (*DATAPacket, device.MessageID, error) {
	session, found := transport.networkLayer.GetSession(sessionID)
	if !found {
		return nil, 0, errors.New("session not found")
	}

	messageID := device.MessageID(transport.dev.Rand().Uint64())
	msg := newOutboxMessage(session.SessionID, messageID, message)

	state := transport.SessionState(session.SessionID)

	nextSeqID := state.DeliverMessage(transport, msg)
	dataPacket := NewDATAPacket(nextSeqID, msg.body)
	return dataPacket, messageID, nil
}

func (transport *TransportLayer) SendMessage(sessionID device.SessionID, message []byte) (device.MessageID, error) {
	dataPacket, messageID, err := transport.newMessage(sessionID, message)
	if err != nil {
		return 0, err
	}

	if err := transport.networkLayer.SendData(sessionID, dataPacket.EncodePacket()); err != nil {
		return 0, err
	}

	return messageID, nil
}

// func (transport *TransportLayer) NewContact(sharedSecret device.SharedSecret) (device.ContactID, error) {
// 	return transport.networkLayer.NewContact(sharedSecret)
// }

func (transport *TransportLayer) DeleteContact(contact device.ContactID) {
	transport.networkLayer.DeleteContact(contact)
}
