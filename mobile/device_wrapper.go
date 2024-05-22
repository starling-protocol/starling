package mobile

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"io"
	"math/rand"
	"time"

	"github.com/starling-protocol/starling/device"
)

type Device interface {
	Log(message string)
	MaxPacketSize(address string) (int, error)
	ProcessMessage(session int64, message []byte)
	SendPacket(address string, packet []byte)
	SessionRequested(session int64, contact string) []byte
	SessionEstablished(session int64, contact string, address string)
	SessionBroken(session int64)
	MessageDelivered(messageID int64)
	SyncStateChanged(contact string, stateUpdate []byte)
}

type deviceWrapper struct {
	dev               Device
	contactsContainer *contactsContainerWrapper
	random            *rand.Rand
}

func newDeviceWrapper(dev Device, contactsContainer ContactsContainer) *deviceWrapper {
	return &deviceWrapper{
		dev:               dev,
		contactsContainer: newContactsContainerWrapper(contactsContainer),
		random:            rand.New(rand.NewSource(rand.Int63())),
	}
}

// Log implements device.Device.
func (d *deviceWrapper) Log(message string) {
	d.dev.Log(message)
}

// MaxPacketSize implements device.Device.
func (d *deviceWrapper) MaxPacketSize(address device.DeviceAddress) (int, error) {
	return d.dev.MaxPacketSize(string(address))
}

// ProcessMessage implements device.Device.
func (d *deviceWrapper) ProcessMessage(session device.SessionID, message []byte) {
	d.dev.ProcessMessage(int64(session), message)
}

// ReplyPayload implements device.Device.
func (d *deviceWrapper) ReplyPayload(session device.SessionID, contact device.ContactID) []byte {
	return d.dev.SessionRequested(int64(session), string(contact))
}

// SessionEstablished implements device.Device.
func (d *deviceWrapper) SessionEstablished(session device.SessionID, contact device.ContactID, address device.DeviceAddress) {
	d.dev.SessionEstablished(int64(session), string(contact), string(address))
}

// SessionBroken implements device.Device.
func (d *deviceWrapper) SessionBroken(session device.SessionID) {
	d.dev.SessionBroken(int64(session))
}

// SyncStateChanged implements device.Device.
func (d *deviceWrapper) SyncStateChanged(contact device.ContactID, stateUpdate []byte) {
	d.dev.SyncStateChanged(string(contact), stateUpdate)
}

// Rand implements device.Device.
func (d *deviceWrapper) Rand() *rand.Rand {
	if d.random == nil {
		var buf [8]byte
		if _, err := crypto_rand.Read(buf[:]); err != nil {
			panic("failed to seed random number")
		}

		seed := binary.BigEndian.Uint64(buf[:])
		d.random = rand.New(rand.NewSource(int64(seed)))
	}

	return d.random
}

// CryptoRand implements device.Device.
func (*deviceWrapper) CryptoRand() io.Reader {
	return crypto_rand.Reader
}

// SendPacket implements device.Device.
func (d *deviceWrapper) SendPacket(address device.DeviceAddress, packet []byte) {
	d.dev.SendPacket(string(address), packet)
}

// MessageDelivered implements device.Device.
func (d *deviceWrapper) MessageDelivered(messageID device.MessageID) {
	d.dev.MessageDelivered(int64(messageID))
}

// Delay implements device.Device.
func (*deviceWrapper) Delay(action func(), duration time.Duration) {
	go func() {
		time.Sleep(duration)
		action()
	}()
}

// Now implements device.Device.
func (*deviceWrapper) Now() time.Time {
	return time.Now()
}

// ContactsContainer implements device.Device.
func (d *deviceWrapper) ContactsContainer() device.ContactsContainer {
	return d.contactsContainer
}
