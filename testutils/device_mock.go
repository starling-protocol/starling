package testutils

import (
	"io"
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/starling-protocol/starling/device"
)

type DeviceMock struct {
	t                   testing.TB
	random              *rand.Rand
	Contacts            *device.MemoryContactsContainer
	PacketsSent         [][]byte
	PacketsReceived     []device.MessageID
	MessagesReceived    [][]byte
	Sessions            []device.SessionID
	SessionsEstablished int
	SessionsBroken      int
	DelayActions        []func()
	SyncState           map[device.ContactID][]byte
}

func NewDeviceMock(t testing.TB, random *rand.Rand) *DeviceMock {
	return &DeviceMock{
		t:                   t,
		random:              random,
		Contacts:            device.NewMemoryContactsContainer(),
		PacketsSent:         [][]byte{},
		MessagesReceived:    [][]byte{},
		Sessions:            []device.SessionID{},
		SessionsEstablished: 0,
		SessionsBroken:      0,
		DelayActions:        []func(){},
		SyncState:           map[device.ContactID][]byte{},
	}
}

// CryptoRand implements device.Device.
func (d *DeviceMock) CryptoRand() io.Reader {
	return d.random
}

// Log implements device.Device.
func (d *DeviceMock) Log(message string) {
	d.t.Log(message)
}

// MaxPacketSize implements device.Device.
func (d *DeviceMock) MaxPacketSize(address device.DeviceAddress) (int, error) {
	return 514, nil
}

// ProcessMessage implements device.Device.
func (d *DeviceMock) ProcessMessage(session device.SessionID, message []byte) {
	d.Log("Process message")
	d.MessagesReceived = append(d.MessagesReceived, message)
}

// Rand implements device.Device.
func (d *DeviceMock) Rand() *rand.Rand {
	return d.random
}

// SendPacket implements device.Device.
func (d *DeviceMock) SendPacket(address device.DeviceAddress, packet []byte) {
	d.PacketsSent = append(d.PacketsSent, packet)
}

// PacketReceived implements device.Device.
func (d *DeviceMock) MessageDelivered(messageID device.MessageID) {
	d.PacketsReceived = append(d.PacketsReceived, messageID)
}

// ReplyPayload implements device.Device.
func (d *DeviceMock) ReplyPayload(session device.SessionID, contact device.ContactID) []byte {
	d.Log("Session requested")
	return nil
}

// SessionEstablished implements device.Device.
func (d *DeviceMock) SessionEstablished(session device.SessionID, contact device.ContactID, address device.DeviceAddress) {
	d.SessionsEstablished += 1
	d.Sessions = append(d.Sessions, session)
}

// SessionBroken implements device.Device.
func (d *DeviceMock) SessionBroken(session device.SessionID) {
	d.SessionsBroken += 1

	idx := slices.Index(d.Sessions, session)
	if idx != -1 {
		d.Sessions = slices.Delete(d.Sessions, idx, idx+1)
	}
}

// SyncStateChanged implements device.Device.
func (d *DeviceMock) SyncStateChanged(contact device.ContactID, stateUpdate []byte) {
	d.SyncState[contact] = stateUpdate
}

// Delay implements device.Device.
func (d *DeviceMock) Delay(action func(), duration time.Duration) {
	// d.t.Logf("Delay by %s", duration.String())

	d.DelayActions = append(d.DelayActions, action)
}

// Now implements device.Device.
func (d *DeviceMock) Now() time.Time {
	return time.Now()
}

// ContactsContainer implements device.Device.
func (d *DeviceMock) ContactsContainer() device.ContactsContainer {
	return d.Contacts
}

func (d *DeviceMock) PopLastPacket() []byte {
	if len(d.PacketsSent) == 0 {
		d.t.Fatalf("Attempted to pop a message from an empty list in device")
	}
	packet := d.PacketsSent[len(d.PacketsSent)-1]
	d.PacketsSent = d.PacketsSent[:len(d.PacketsSent)-1]
	return packet
}

func (d *DeviceMock) ExecuteNextDelayAction() {
	if len(d.DelayActions) == 0 {
		d.t.Fatalf("Attempted to execute a delay action, but delay action list is empty")
	}
	action := d.DelayActions[0]
	d.DelayActions = d.DelayActions[1:]
	action()
}
