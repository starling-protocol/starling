package network_layer_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/network_layer"
	"github.com/starling-protocol/starling/testutils"

	"github.com/stretchr/testify/assert"
)

type mockNetEvents struct {
	dev                 *testutils.DeviceMock
	replyPayload        []byte
	sessionsEstablished int
	sessionsBroken      int
}

func newMockNetEvents(dev *testutils.DeviceMock) *mockNetEvents {
	return &mockNetEvents{
		dev:          dev,
		replyPayload: nil,
	}
}

// ReplyPayload implements network_layer.NetworkLayerEvents.
func (e *mockNetEvents) ReplyPayload(session device.SessionID, contact device.ContactID) []byte {
	return e.replyPayload
}

// SessionBroken implements network_layer.NetworkLayerEvents.
func (e *mockNetEvents) SessionBroken(session device.SessionID) {
	e.sessionsBroken += 1
}

// SessionEstablished implements network_layer.NetworkLayerEvents.
func (e *mockNetEvents) SessionEstablished(session device.SessionID, contact device.ContactID, address device.DeviceAddress, payload []byte, isInitiator bool) {
	e.sessionsEstablished += 1
}

type TestNode struct {
	address      device.DeviceAddress
	networkLayer *network_layer.NetworkLayer
	dev          *testutils.DeviceMock
	netEvents    *mockNetEvents
	contact      device.ContactID
}

func NewTestNode(address device.DeviceAddress, networkLayer *network_layer.NetworkLayer, dev *testutils.DeviceMock, netEvents *mockNetEvents, contact device.ContactID) *TestNode {
	return &TestNode{
		address:      address,
		networkLayer: networkLayer,
		dev:          dev,
		netEvents:    netEvents,
		contact:      contact,
	}
}

func setupNodes(t *testing.T, random *rand.Rand, addressA device.DeviceAddress, addressB device.DeviceAddress) (*TestNode, *TestNode) {
	protoOptions := *device.DefaultProtocolOptions()
	protoOptions.DisableAutoRREQOnConnection = true

	devA := testutils.NewDeviceMock(t, random)
	netEventsA := newMockNetEvents(devA)
	netLayerA := network_layer.NewNetworkLayer(devA, netEventsA, protoOptions)

	devB := testutils.NewDeviceMock(t, random)
	netEventsB := newMockNetEvents(devB)
	netLayerB := network_layer.NewNetworkLayer(devB, netEventsB, protoOptions)

	// Create contacts
	var secret [32]byte
	random.Read(secret[:])

	contactA := devA.Contacts.DebugLink(secret[:])
	contactB := devB.Contacts.DebugLink(secret[:])

	assert.Equal(t, contactA, contactB)

	nodeA := NewTestNode(addressA, netLayerA, devA, netEventsA, contactA)
	nodeB := NewTestNode(addressB, netLayerB, devB, netEventsB, contactB)

	return nodeA, nodeB
}

func establishSession(t *testing.T, nodeA *TestNode, nodeB *TestNode) {
	// Establish session
	nodeA.networkLayer.OnConnection(nodeB.address)
	nodeB.networkLayer.OnConnection(nodeA.address)

	nodeA.networkLayer.BroadcastRouteRequest()

	nodeB.networkLayer.ReceivePacket(nodeA.address, nodeA.dev.PopLastPacket())
	nodeA.networkLayer.ReceivePacket(nodeB.address, nodeB.dev.PopLastPacket())

	assert.Len(t, nodeA.networkLayer.AllSessions(nodeA.contact), 1)
	assert.ElementsMatch(t, nodeA.networkLayer.AllSessions(nodeA.contact), nodeB.networkLayer.AllSessions(nodeB.contact))
}

func TestSessionEstablishment(t *testing.T) {
	seed := rand.NewSource(rand.Int63())
	random := rand.New(seed)
	t.Logf("Testing with seed: %d", seed.Int63())

	addressA := device.DeviceAddress("1000")
	addressB := device.DeviceAddress("2000")
	nodeA, nodeB := setupNodes(t, random, addressA, addressB)

	assert.Empty(t, nodeA.networkLayer.AllSessions(nodeA.contact))
	assert.Empty(t, nodeB.networkLayer.AllSessions(nodeB.contact))

	establishSession(t, nodeA, nodeB)
}

func TestRouteReplyAuthentication(t *testing.T) {
	seed := rand.NewSource(rand.Int63())
	random := rand.New(seed)
	t.Logf("Testing with seed: %d", seed.Int63())

	addressA := device.DeviceAddress("1000")
	addressB := device.DeviceAddress("2000")
	nodeA, nodeB := setupNodes(t, random, addressA, addressB)
	nodeB.netEvents.replyPayload = []byte("reply payload here")

	nodeA.networkLayer.OnConnection(nodeB.address)
	nodeB.networkLayer.OnConnection(nodeA.address)

	nodeA.networkLayer.BroadcastRouteRequest()
	nodeB.networkLayer.ReceivePacket(nodeA.address, nodeA.dev.PopLastPacket())

	// attempt to alter route reply
	rrep := nodeB.dev.PopLastPacket()
	for i := 0; i < len(rrep); i++ {
		alteredRREP := bytes.Clone(rrep)
		alteredRREP[i] += 1

		nodeA.networkLayer.ReceivePacket(nodeB.address, alteredRREP)
		assert.Equalf(t, 0, nodeA.netEvents.sessionsEstablished, "altered route reply should be ignored, byte %d", i)
	}

	assert.Empty(t, nodeA.networkLayer.AllSessions(nodeA.contact))
}
