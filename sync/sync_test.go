package sync_test

import (
	"crypto/ed25519"
	"math/rand"
	"testing"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/sync"

	"github.com/stretchr/testify/assert"
)

type mockSyncEventPushUpdate struct {
	contact    device.ContactID
	session    device.SessionID
	pushPacket *sync.PushPacket
}

type mockSyncEventStateChange struct {
	contact      device.ContactID
	updatedState []byte
}

type mockSyncEvents struct {
	contactDiscoverEvents []device.ContactID
	pushUpdates           []mockSyncEventPushUpdate
	stateChanges          []mockSyncEventStateChange
}

// Log implements sync.SyncEvents.
func (m *mockSyncEvents) Log(message string) {}

func (m *mockSyncEvents) AssertEmpty(t *testing.T) {
	assert.Empty(t, m.pushUpdates, "push update should be empty")
	assert.Empty(t, m.stateChanges, "state changes should be empty")
	assert.Empty(t, m.contactDiscoverEvents, "contact discover events should be empty")
}

// DiscoverContact implements sync.SyncEvents.
func (m *mockSyncEvents) DiscoverContact(contact device.ContactID) {
	m.contactDiscoverEvents = append(m.contactDiscoverEvents, contact)
}

func (m *mockSyncEvents) PopContactDiscoverEvent(t *testing.T) device.ContactID {
	assert.NotEmpty(t, m.contactDiscoverEvents)

	contact := m.contactDiscoverEvents[0]
	m.contactDiscoverEvents = m.contactDiscoverEvents[1:]
	return contact
}

// PushSyncUpdates implements sync.SyncEvents.
func (m *mockSyncEvents) PushSyncUpdates(contact device.ContactID, session device.SessionID, pushPacket *sync.PushPacket) {
	m.pushUpdates = append(m.pushUpdates, mockSyncEventPushUpdate{
		contact:    contact,
		session:    session,
		pushPacket: pushPacket,
	})
}

func (m *mockSyncEvents) PopPushUpdate(t *testing.T) *mockSyncEventPushUpdate {
	assert.NotEmpty(t, m.pushUpdates)

	update := m.pushUpdates[0]
	m.pushUpdates = m.pushUpdates[1:]
	return &update
}

// SyncStateChanged implements sync.SyncEvents.
func (m *mockSyncEvents) SyncStateChanged(contact device.ContactID, updatedState []byte) {
	m.stateChanges = append(m.stateChanges, mockSyncEventStateChange{
		contact:      contact,
		updatedState: updatedState,
	})
}

func (m *mockSyncEvents) PopStateChange(t *testing.T) *mockSyncEventStateChange {
	assert.NotEmpty(t, m.stateChanges)

	stateChange := m.stateChanges[0]
	m.stateChanges = m.stateChanges[1:]
	return &stateChange
}

func newPrivateKey(t testing.TB, random *rand.Rand) ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(random)
	assert.NoError(t, err)
	return priv
}

func newPublicKey(t testing.TB, random *rand.Rand) sync.NodePublicKey {
	return sync.ExtractNodePublicKey(newPrivateKey(t, random))
}

func TestSyncNewContact(t *testing.T) {
	random := rand.New(rand.NewSource(1234))

	syncState := sync.NewSync(&mockSyncEvents{})
	syncState.NewContact("CONTACT_ID", newPrivateKey(t, random), sync.ModelTypeLink)

	state, err := syncState.ContactState("CONTACT_ID")
	assert.NoError(t, err)
	assert.EqualValues(t, string(state), `{"digests":{},"private_key":"wA5dZ8J1U4mt7X2LFRy9W8337Sda1eAotmSID8dYHHc+tpp38Suyk6yRtra6iOBljXRTV0d4JAIXKnkQI3fG3g==","public_key":"Praad/ErspOskba2uojgZY10U1dHeCQCFyp5ECN3xt4=","node_states":{},"type":"link"}`)
}

func TestSyncNewMessage(t *testing.T) {
	random := rand.New(rand.NewSource(1234))

	syncState := sync.NewSync(&mockSyncEvents{})
	syncState.NewContact("CONTACT_ID", newPrivateKey(t, random), sync.ModelTypeLink)
	syncState.NewMessage("CONTACT_ID", []byte("message"), nil)

	state, err := syncState.ContactState("CONTACT_ID")
	assert.NoError(t, err)
	assert.EqualValues(t, string(state), `{"digests":{"Praad/ErspOskba2uojgZY10U1dHeCQCFyp5ECN3xt4=":{"nodes":{"Praad/ErspOskba2uojgZY10U1dHeCQCFyp5ECN3xt4=":1},"max_version":1}},"private_key":"wA5dZ8J1U4mt7X2LFRy9W8337Sda1eAotmSID8dYHHc+tpp38Suyk6yRtra6iOBljXRTV0d4JAIXKnkQI3fG3g==","public_key":"Praad/ErspOskba2uojgZY10U1dHeCQCFyp5ECN3xt4=","node_states":{"Praad/ErspOskba2uojgZY10U1dHeCQCFyp5ECN3xt4=":{"1":{"value":"bWVzc2FnZQ==","sig":"hGgfUXMXFhCrLfcjuRcGfJ3X6XKXSOhJor3yoL9g2dvlHd5x2EYHxzoe/g+7DWWkwPc9KGqTl2pyRp7GELmvCg==","attached_secret":null}}},"type":"link"}`)
}

func syncAPullB(t *testing.T, syncA *sync.Sync, syncB *sync.Sync, eventsA *mockSyncEvents, eventsB *mockSyncEvents, contact device.ContactID, session device.SessionID) {
	// A makes pull packet to B
	pullPacket, err := syncA.PullPacket(contact)
	assert.NoError(t, err)
	pullPacketBytes := pullPacket.Encode()

	// B receives pull packet
	err = syncB.ReceiveSyncPacket(contact, session, pullPacketBytes)
	assert.NoError(t, err)

	// B generates a push packet to A
	pushUpdate := eventsB.PopPushUpdate(t)
	assert.LessOrEqual(t, len(eventsB.stateChanges), 1)
	assert.Empty(t, eventsB.pushUpdates)
	eventsB.stateChanges = []mockSyncEventStateChange{}

	// A receives push packet
	pushPacketBytes := pushUpdate.pushPacket.Encode()
	err = syncA.ReceiveSyncPacket(contact, session, pushPacketBytes)
	assert.NoError(t, err)

	eventsA.PopStateChange(t)
}

func TestSyncPacketExchange(t *testing.T) {
	seed := rand.NewSource(rand.Int63())
	random := rand.New(seed)
	t.Logf("Testing with seed: %d", seed.Int63())

	eventsA := &mockSyncEvents{}
	eventsB := &mockSyncEvents{}

	syncA := sync.NewSync(eventsA)
	syncB := sync.NewSync(eventsB)

	contactAB := device.ContactID("contactAB")

	session := device.SessionID(1234)

	syncA.NewContact(contactAB, newPrivateKey(t, random), sync.ModelTypeLink)
	syncB.NewContact(contactAB, newPrivateKey(t, random), sync.ModelTypeLink)
	eventsA.PopStateChange(t)
	eventsB.PopStateChange(t)

	syncA.NewMessage(contactAB, []byte("hello from A"), nil)
	syncB.NewMessage(contactAB, []byte("hello from B"), nil)
	eventsA.PopStateChange(t)
	eventsB.PopStateChange(t)
	eventsA.PopContactDiscoverEvent(t)
	eventsB.PopContactDiscoverEvent(t)

	syncAPullB(t, syncA, syncB, eventsA, eventsB, contactAB, session)
	eventsA.AssertEmpty(t)
	eventsB.AssertEmpty(t)

	syncAPullB(t, syncB, syncA, eventsB, eventsA, contactAB, session)
	eventsB.pushUpdates = []mockSyncEventPushUpdate{}
	eventsA.AssertEmpty(t)
	eventsB.AssertEmpty(t)
}

// A, B, C are in a group. The network looks like: A <-> B <-> C.
// When A sends a message, C should receive it from B.
func TestTransitiveSyncPacketExchange(t *testing.T) {
	seed := rand.NewSource(rand.Int63())
	random := rand.New(seed)
	t.Logf("Testing with seed: %d", seed.Int63())

	eventsA := &mockSyncEvents{}
	eventsB := &mockSyncEvents{}
	eventsC := &mockSyncEvents{}

	syncA := sync.NewSync(eventsA)
	syncB := sync.NewSync(eventsB)
	syncC := sync.NewSync(eventsC)

	groupContact := device.ContactID("groupContact")

	syncA.NewContact(groupContact, newPrivateKey(t, random), sync.ModelTypeGroup)
	syncB.NewContact(groupContact, newPrivateKey(t, random), sync.ModelTypeGroup)
	syncC.NewContact(groupContact, newPrivateKey(t, random), sync.ModelTypeGroup)

	eventsA.PopStateChange(t)
	eventsB.PopStateChange(t)
	eventsC.PopStateChange(t)

	sessionAB := device.SessionID(1234)
	sessionBC := device.SessionID(2345)

	syncA.NewMessage(groupContact, []byte("hello from A"), nil)
	syncB.NewMessage(groupContact, []byte("hello from B"), nil)
	syncC.NewMessage(groupContact, []byte("hello from C"), nil)

	eventsA.PopStateChange(t)
	eventsB.PopStateChange(t)
	eventsC.PopStateChange(t)
	eventsA.PopContactDiscoverEvent(t)
	eventsB.PopContactDiscoverEvent(t)
	eventsC.PopContactDiscoverEvent(t)

	// C pulls from B in order to establish a sync session
	syncAPullB(t, syncC, syncB, eventsC, eventsB, groupContact, sessionBC)

	eventsC.AssertEmpty(t)
	eventsB.AssertEmpty(t)

	// Now, when B pulls from A and receives "hello from A",
	// the message should automatically be forwarded to C from B.
	syncAPullB(t, syncB, syncA, eventsB, eventsA, groupContact, sessionAB)

	eventsA.AssertEmpty(t)

	// A's message from B to C
	pushUpdate := eventsB.PopPushUpdate(t)
	eventsB.AssertEmpty(t)

	assert.Equal(t, pushUpdate.session, sessionBC)

	pushPacketBytes := pushUpdate.pushPacket.Encode()
	err := syncC.ReceiveSyncPacket(groupContact, pushUpdate.session, pushPacketBytes)
	assert.NoError(t, err)

	eventsC.PopStateChange(t)
	eventsC.AssertEmpty(t)
}
