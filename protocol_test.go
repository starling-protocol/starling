package starling_test

import (
	"encoding/json"
	"math/rand"
	"testing"

	"github.com/starling-protocol/starling"
	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/sync"
	"github.com/starling-protocol/starling/testutils"

	"github.com/stretchr/testify/assert"
)

func linkProtocols(t *testing.T, protoA *starling.Protocol, protoB *starling.Protocol) device.ContactID {
	sessA, err := protoA.LinkingStart()
	assert.NoError(t, err)

	sessB, err := protoB.LinkingStart()
	assert.NoError(t, err)

	contactB, err := protoB.LinkingCreate(sessB, sessA.GetShare())
	assert.NoError(t, err)

	contactA, err := protoA.LinkingCreate(sessA, sessB.GetShare())
	assert.NoError(t, err)

	assert.Equal(t, contactA, contactB)

	return contactA
}

func TestLinking(t *testing.T) {
	seed := rand.NewSource(rand.Int63())
	random := rand.New(seed)
	t.Logf("Testing with seed: %d", seed.Int63())

	devA := testutils.NewDeviceMock(t, random)
	protoA := starling.NewProtocol(devA, nil)

	devB := testutils.NewDeviceMock(t, random)
	protoB := starling.NewProtocol(devB, nil)

	contact := linkProtocols(t, protoA, protoB)

	assert.NotEmpty(t, contact)
}

func TestOnConnection(t *testing.T) {
	seed := rand.NewSource(rand.Int63())
	random := rand.New(seed)
	t.Logf("Testing with seed: %d", seed.Int63())

	devA := testutils.NewDeviceMock(t, random)
	protoA := starling.NewProtocol(devA, nil)

	devB := testutils.NewDeviceMock(t, random)
	protoB := starling.NewProtocol(devB, nil)

	linkProtocols(t, protoA, protoB)

	protoA.OnConnection("addressB")
	assert.Len(t, devA.PacketsSent, 1)
	assert.Len(t, devB.PacketsSent, 0)

	protoA.OnDisconnection("addressB")
}

func TestDeleteContact(t *testing.T) {
	seed := rand.NewSource(rand.Int63())
	random := rand.New(seed)
	t.Logf("Testing with seed: %d", seed.Int63())

	devA := testutils.NewDeviceMock(t, random)
	protoA := starling.NewProtocol(devA, device.DefaultSyncProtocolOptions())

	devB := testutils.NewDeviceMock(t, random)
	protoB := starling.NewProtocol(devB, device.DefaultSyncProtocolOptions())

	// Link devices
	contact := linkProtocols(t, protoA, protoB)
	assert.Len(t, devA.Contacts.AllLinks(), 1)
	assert.NotNil(t, devA.SyncState[contact])
	assert.Greater(t, len(devA.SyncState[contact]), 100)

	err := json.Unmarshal(devA.SyncState[contact], &sync.Model{})
	assert.NoError(t, err)

	// Establish connection
	protoA.OnConnection("addressB")
	protoB.OnConnection("addressA")
	protoA.BroadcastRouteRequest()
	protoB.ReceivePacket("addressA", devA.PopLastPacket())
	protoA.ReceivePacket("addressB", devB.PopLastPacket())
	assert.Len(t, devA.Sessions, 1)

	// Delete contact
	protoA.DeleteContact(contact)
	assert.Empty(t, devA.Contacts.AllLinks())
	assert.Nil(t, devA.SyncState[contact])

	assert.Empty(t, devA.Sessions)
}

func TestSendGroupInvite(t *testing.T) {
	seed := rand.NewSource(rand.Int63())
	random := rand.New(seed)
	t.Logf("Testing with seed: %d", seed.Int63())

	devA := testutils.NewDeviceMock(t, random)
	protoA := starling.NewProtocol(devA, device.DefaultSyncProtocolOptions())

	devB := testutils.NewDeviceMock(t, random)
	protoB := starling.NewProtocol(devB, device.DefaultSyncProtocolOptions())

	// Link devices
	contact := linkProtocols(t, protoA, protoB)
	assert.Len(t, devA.Contacts.AllLinks(), 1)

	// Create group and invite contact
	groupID, err := protoA.NewGroup()
	assert.NoError(t, err)

	err = protoA.SyncAddMessage(contact, []byte("Invite"), &groupID)
	assert.NoError(t, err)

	var state sync.Model
	err = json.Unmarshal(devA.SyncState[contact], &state)
	assert.NoError(t, err)
	assert.Len(t, state.NodeStates[state.PublicKey], 1)

	groupSecret := state.NodeStates[state.PublicKey][sync.Version(1)].AttachedSecret
	assert.NotNil(t, groupSecret)

	groupID2, err := protoB.JoinGroup(groupSecret)
	assert.NoError(t, err)
	assert.Equal(t, groupID, groupID2)
}
