package transport_layer_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/testutils"
	"github.com/starling-protocol/starling/transport_layer"

	"github.com/stretchr/testify/assert"
)

type TestNode struct {
	address        device.DeviceAddress
	transportLayer *transport_layer.TransportLayer
	dev            *testutils.DeviceMock
	contact        device.ContactID
	session        device.SessionID
}

func NewTestNode(address device.DeviceAddress, transportLayer *transport_layer.TransportLayer, dev *testutils.DeviceMock, contact device.ContactID, session device.SessionID) *TestNode {
	return &TestNode{
		address:        address,
		transportLayer: transportLayer,
		dev:            dev,
		contact:        contact,
		session:        session,
	}
}

func setupConnection(t *testing.T, addressA device.DeviceAddress, addressB device.DeviceAddress) (*TestNode, *TestNode) {
	seed := rand.NewSource(rand.Int63())
	random := rand.New(seed)
	t.Logf("Testing with seed: %d", seed.Int63())
	sharedSecret := bytes.Repeat([]byte{0x01}, 32)
	protoOptions := device.DefaultProtocolOptions()
	protoOptions.DisableAutoRREQOnConnection = true

	devA := testutils.NewDeviceMock(t, random)
	transportLayerA := transport_layer.NewTransportLayer(devA, transportEvents{devA}, *protoOptions)
	contactA := devA.Contacts.DebugLink(sharedSecret)

	devB := testutils.NewDeviceMock(t, random)
	transportLayerB := transport_layer.NewTransportLayer(devB, transportEvents{devB}, *protoOptions)
	contactB := devB.Contacts.DebugLink(sharedSecret)

	assert.Equal(t, contactA, contactB)

	transportLayerA.OnConnection(addressB)
	transportLayerB.OnConnection(addressA)
	transportLayerA.BroadcastRouteRequest()

	// RREQ
	transportLayerB.ReceivePacket(addressA, devA.PopLastPacket())

	// RREP
	transportLayerA.ReceivePacket(addressB, devB.PopLastPacket())

	// Delay for sending ACK of RREP
	devA.ExecuteNextDelayAction()

	// ACK for RREP
	transportLayerB.ReceivePacket(addressA, devA.PopLastPacket())

	// Delay for ACK timeout
	devB.ExecuteNextDelayAction()

	assert.Empty(t, devA.DelayActions)
	assert.Empty(t, devB.DelayActions)

	nodeA := NewTestNode(addressA, transportLayerA, devA, contactA, devA.Sessions[0])
	nodeB := NewTestNode(addressB, transportLayerB, devB, contactB, devA.Sessions[0])
	return nodeA, nodeB
}

func TestBasicTransport(t *testing.T) {
	addressA := device.DeviceAddress("1000")
	addressB := device.DeviceAddress("2000")
	nodeA, nodeB := setupConnection(t, addressA, addressB)

	nodeA.transportLayer.SendMessage(nodeA.session, []byte("Hello from A"))
	assert.NotEmpty(t, nodeA.dev.PacketsSent)
	receivedMessages := nodeB.transportLayer.ReceivePacket(addressA, nodeA.dev.PopLastPacket())
	assert.NotEmpty(t, receivedMessages)
	assert.Equal(t, receivedMessages[0].Data, []byte("Hello from A"))

	nodeB.dev.ExecuteNextDelayAction()
	assert.NotEmpty(t, nodeB.dev.PacketsSent)
	nodeA.transportLayer.ReceivePacket(addressB, nodeB.dev.PopLastPacket())
	assert.NotEmpty(t, nodeA.dev.PacketsReceived)
}

func TestTimeout(t *testing.T) {
	addressA := device.DeviceAddress("1000")
	addressB := device.DeviceAddress("2000")
	nodeA, nodeB := setupConnection(t, addressA, addressB)

	// A sends a messag to B
	receivedMessages := sendAndReceiveMessage(t, "Message 1", nodeA, nodeB)
	assert.NotEmpty(t, receivedMessages)
	assert.Equal(t, receivedMessages[0].Data, []byte("Message 1"))
	assert.Equal(t, 0, nodeA.dev.SessionsBroken)

	// A times out waiting for ack from B
	nodeA.dev.ExecuteNextDelayAction()
	assert.Equal(t, 1, nodeA.dev.SessionsBroken)
}

// A sends two packets, but the first is initially dropped
func TestSingleDataPacketDrop(t *testing.T) {
	addressA := device.DeviceAddress("1000")
	addressB := device.DeviceAddress("2000")
	nodeA, nodeB := setupConnection(t, addressA, addressB)

	// A sends first packet
	nodeA.transportLayer.SendMessage(nodeA.session, []byte("Hello from A"))
	assert.NotEmpty(t, nodeA.dev.PacketsSent)

	// Packet is dropped, and B does not receive the message
	nodeA.dev.PopLastPacket()
	assert.Empty(t, nodeA.dev.PacketsSent)

	// A sends second packet, and this is received by B (however not delivered yet)
	nodeA.transportLayer.SendMessage(nodeA.session, []byte("This is the second message"))
	assert.NotEmpty(t, nodeA.dev.PacketsSent)
	receivedMessages := nodeB.transportLayer.ReceivePacket(addressA, nodeA.dev.PopLastPacket())
	assert.Empty(t, receivedMessages)

	// B's ack timer times out, and it replies with an ACK (containing the sequence numbers of the missing packets)
	nodeB.dev.ExecuteNextDelayAction()
	assert.NotEmpty(t, nodeB.dev.PacketsSent)
	nodeA.transportLayer.ReceivePacket(addressB, nodeB.dev.PopLastPacket())
	assert.NotEmpty(t, nodeA.dev.PacketsReceived)

	// A responds by resending the initial message
	assert.NotEmpty(t, nodeA.dev.PacketsSent)
	receivedMessages = nodeB.transportLayer.ReceivePacket(addressA, nodeA.dev.PopLastPacket())
	assert.Equal(t, len(receivedMessages), 2)
	assert.Equal(t, receivedMessages[0].Data, []byte("Hello from A"))
	assert.Equal(t, receivedMessages[1].Data, []byte("This is the second message"))
}

// Message 3 and message 5 is dropped.
func TestMultiDataPacketDrop(t *testing.T) {
	addressA := device.DeviceAddress("1000")
	addressB := device.DeviceAddress("2000")
	nodeA, nodeB := setupConnection(t, addressA, addressB)

	// A sends first and second packet, and B acks it
	receivedMessages := sendAndReceiveMessage(t, "Message 1", nodeA, nodeB)
	assert.NotEmpty(t, receivedMessages)
	assert.Equal(t, receivedMessages[0].Data, []byte("Message 1"))

	receivedMessages = sendAndReceiveMessage(t, "Message 2", nodeA, nodeB)
	assert.NotEmpty(t, receivedMessages)
	assert.Equal(t, receivedMessages[0].Data, []byte("Message 2"))
	ackMessage(t, nodeA, nodeB)

	// A sends third packet.
	nodeA.transportLayer.SendMessage(nodeA.session, []byte("Message 3"))
	assert.NotEmpty(t, nodeA.dev.PacketsSent)

	// Packet is dropped, and B does not receive the message
	nodeA.dev.PopLastPacket()
	assert.Empty(t, nodeA.dev.PacketsSent)

	// A sends fourth packet
	receivedMessages = sendAndReceiveMessage(t, "Message 4", nodeA, nodeB)
	assert.Empty(t, receivedMessages)

	// A sends fifth packet
	nodeA.transportLayer.SendMessage(nodeA.session, []byte("Message 5"))
	assert.NotEmpty(t, nodeA.dev.PacketsSent)

	// Packet is dropped, and B does not receive the message
	nodeA.dev.PopLastPacket()
	assert.Empty(t, nodeA.dev.PacketsSent)

	// A sends sixth packet.
	receivedMessages = sendAndReceiveMessage(t, "Message 6", nodeA, nodeB)
	assert.Empty(t, receivedMessages)

	// B sends an ack which prompts A to respond with the two missing packets
	ackMessage(t, nodeA, nodeB)
	assert.NotEmpty(t, nodeA.dev.PacketsSent)
	packet5 := nodeA.dev.PopLastPacket()
	packet3 := nodeA.dev.PopLastPacket()

	// B receives packet 3 first
	receivedMessages = nodeB.transportLayer.ReceivePacket(nodeA.address, packet3)
	assert.Equal(t, 2, len(receivedMessages))
	assert.Equal(t, receivedMessages[0].Data, []byte("Message 3"))
	assert.Equal(t, receivedMessages[1].Data, []byte("Message 4"))

	// Then packet 5
	receivedMessages = nodeB.transportLayer.ReceivePacket(nodeA.address, packet5)
	assert.Equal(t, 2, len(receivedMessages))
	assert.Equal(t, receivedMessages[0].Data, []byte("Message 5"))
	assert.Equal(t, receivedMessages[1].Data, []byte("Message 6"))
}

// Message 3 and message 5 is dropped as well as the second ack B sends.
func TestMultiDataAndAckPacketDrop(t *testing.T) {
	addressA := device.DeviceAddress("1000")
	addressB := device.DeviceAddress("2000")
	nodeA, nodeB := setupConnection(t, addressA, addressB)

	// A sends first and second packet, and B acks it
	receivedMessages := sendAndReceiveMessage(t, "Message 1", nodeA, nodeB)
	assert.NotEmpty(t, receivedMessages)
	assert.Equal(t, receivedMessages[0].Data, []byte("Message 1"))

	receivedMessages = sendAndReceiveMessage(t, "Message 2", nodeA, nodeB)
	assert.NotEmpty(t, receivedMessages)
	assert.Equal(t, receivedMessages[0].Data, []byte("Message 2"))
	ackMessage(t, nodeA, nodeB)

	// A sends third packet.
	nodeA.transportLayer.SendMessage(nodeA.session, []byte("Message 3"))
	assert.NotEmpty(t, nodeA.dev.PacketsSent)

	// Packet is dropped, and B does not receive the message
	nodeA.dev.PopLastPacket()
	assert.Empty(t, nodeA.dev.PacketsSent)

	// A sends fourth packet
	receivedMessages = sendAndReceiveMessage(t, "Message 4", nodeA, nodeB)
	assert.Empty(t, receivedMessages)

	// B sends ack, but it is dropped
	nodeB.dev.ExecuteNextDelayAction()
	assert.NotEmpty(t, nodeB.dev.PacketsSent)
	nodeB.dev.PopLastPacket()

	// A sends fifth packet
	nodeA.transportLayer.SendMessage(nodeA.session, []byte("Message 5"))
	assert.NotEmpty(t, nodeA.dev.PacketsSent)

	// Packet is dropped, and B does not receive the message
	nodeA.dev.PopLastPacket()
	assert.Empty(t, nodeA.dev.PacketsSent)

	// A sends sixth packet.
	receivedMessages = sendAndReceiveMessage(t, "Message 6", nodeA, nodeB)
	assert.Empty(t, receivedMessages)

	// B sends an ack which prompts A to respond with the two missing packets
	ackMessage(t, nodeA, nodeB)
	assert.NotEmpty(t, nodeA.dev.PacketsSent)
	packet5 := nodeA.dev.PopLastPacket()
	packet3 := nodeA.dev.PopLastPacket()

	// B receives packet 5 first
	receivedMessages = nodeB.transportLayer.ReceivePacket(nodeA.address, packet5)
	assert.Empty(t, receivedMessages)

	// Then packet 3
	receivedMessages = nodeB.transportLayer.ReceivePacket(nodeA.address, packet3)
	assert.Equal(t, 4, len(receivedMessages))
	assert.Equal(t, receivedMessages[0].Data, []byte("Message 3"))
	assert.Equal(t, receivedMessages[1].Data, []byte("Message 4"))
	assert.Equal(t, receivedMessages[2].Data, []byte("Message 5"))
	assert.Equal(t, receivedMessages[3].Data, []byte("Message 6"))
}

type transportEvents struct {
	dev device.Device
}

// SessionBroken implements transport_layer.TransportEvents.
func (t transportEvents) SessionBroken(session device.SessionID) {
	t.dev.SessionBroken(session)
}

func (t transportEvents) SessionEstablished(session device.SessionID, contact device.ContactID, address device.DeviceAddress, payload []byte, isInitiator bool) {
	t.dev.SessionEstablished(session, contact, address)
}

func (t transportEvents) ReplyPayload(session device.SessionID, contact device.ContactID) []byte {
	return t.dev.ReplyPayload(session, contact)
}

func (t transportEvents) MessageDelivered(messageID device.MessageID) {
	t.dev.MessageDelivered(messageID)
}

func sendAndReceiveMessage(t *testing.T, message string, nodeA *TestNode, nodeB *TestNode) []transport_layer.TransportMessage {
	nodeA.transportLayer.SendMessage(nodeA.session, []byte(message))
	assert.NotEmpty(t, nodeA.dev.PacketsSent)
	receivedMessages := nodeB.transportLayer.ReceivePacket(nodeA.address, nodeA.dev.PopLastPacket())
	return receivedMessages
}

func ackMessage(t *testing.T, nodeA *TestNode, nodeB *TestNode) {
	nodeB.dev.ExecuteNextDelayAction()
	assert.NotEmpty(t, nodeB.dev.PacketsSent)
	nodeA.transportLayer.ReceivePacket(nodeB.address, nodeB.dev.PopLastPacket())
	assert.NotEmpty(t, nodeA.dev.PacketsReceived)
}
