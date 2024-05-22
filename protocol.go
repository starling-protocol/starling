// An implementation of the Starling protocol
package starling

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/starling-protocol/starling/application_layer"
	"github.com/starling-protocol/starling/contacts"
	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/sync"
)

// The main protocol object which keeps the state of the entire protocol stack
type Protocol struct {
	dev         device.Device
	options     device.ProtocolOptions
	application *application_layer.ApplicationLayer
}

// NewProtocol constructs a new Protocol given device and options.
func NewProtocol(dev device.Device, options *device.ProtocolOptions) *Protocol {
	if options == nil {
		options = device.DefaultProtocolOptions()
	}

	return &Protocol{
		dev:         dev,
		options:     *options,
		application: application_layer.NewApplicationLayer(dev, *options),
	}
}

func (proto *Protocol) LoadPersistedState() {
	proto.log("load_persisted_state")
	proto.application.LoadPersistedState()
}

func (proto *Protocol) log(body ...any) {
	proto.dev.Log(fmt.Sprintf("proto:%s", fmt.Sprint(body...)))
}

func (proto *Protocol) logf(msg string, args ...any) {
	proto.log(fmt.Sprintf(msg, args...))
}

// OnConnection should be called when a new link layer connection has been established
// and is ready to receive messages.
func (proto *Protocol) OnConnection(address device.DeviceAddress) {
	proto.logf("on_connection:%s", address)
	proto.application.OnConnection(address)
}

// OnDisconnection should be called when a link layer connection has been broken
// and can no longer receive messages.
func (proto *Protocol) OnDisconnection(address device.DeviceAddress) {
	proto.logf("on_disconnection:%s", address)
	proto.application.OnDisconnection(address)
}

// SendMessage is called to send a message on a session.
// The SessionID is obtained from the OnSessionEstablished function of the Device.
func (proto *Protocol) SendMessage(session device.SessionID, message []byte) (device.MessageID, error) {
	proto.logf("send_message:%d:%s", session, base64.StdEncoding.EncodeToString(message))
	return proto.application.SendMessage(session, message)
}

// BroadcastRouteRequest is called to send a route request to all connected peers.
func (proto *Protocol) BroadcastRouteRequest() {
	proto.log("broadcast_rreq")
	proto.application.BroadcastRouteRequest()
}

// ReceivePacket should be called when a new packet is received on the link layer.
func (proto *Protocol) ReceivePacket(address device.DeviceAddress, packet []byte) {
	proto.logf("receive_packet:%s:%s", address, base64.StdEncoding.EncodeToString(packet))
	proto.application.ReceivePacket(address, packet)
}

// NewGroup creates a new contact which is shared with no one else yet.
func (proto *Protocol) NewGroup() (device.ContactID, error) {
	var secret [32]byte
	n, err := proto.dev.CryptoRand().Read(secret[:])
	if err != nil {
		return "", err
	}

	if n != 32 {
		return "", errors.New("failed to read random bytes for secret")
	}

	return proto.application.JoinGroup(secret[:])
}

// LinkingStart is used to initiate a linking session.
func (proto *Protocol) LinkingStart() (*contacts.LinkingSession, error) {
	proto.log("linking_start")
	return contacts.StartLinking()
}

// LinkingStart is used to finish a linking session and create a common contact.
func (proto *Protocol) LinkingCreate(linkSession *contacts.LinkingSession, remoteKey []byte) (device.ContactID, error) {
	proto.log("linking_create")

	share, err := linkSession.CreateContact(remoteKey)
	if err != nil {
		return "", fmt.Errorf("failed to create link: '%w'", err)
	}

	sharedSecret := device.SharedSecret(share)
	contact, err := proto.dev.ContactsContainer().NewLink(sharedSecret)
	if err != nil {
		return "", fmt.Errorf("failed to store new link: '%w'", err)
	}

	if err := proto.application.ContactCreated(contact, sync.ModelTypeLink); err != nil {
		// roll back and return error
		proto.dev.ContactsContainer().DeleteContact(contact)
		return "", err
	}

	proto.application.BroadcastRouteRequest()

	return contact, nil
}

// DebugLink is only used for testing.
// func (proto *Protocol) DebugLink(sharedSecret device.SharedSecret) device.ContactID {
// 	contact, err := proto.application.NewContact(sharedSecret)
// 	if err != nil {
// 		panic(err)
// 	}

// 	return contact
// }

// DeleteContact deletes the given contact such that future requests from this contact will be ignored.
func (proto *Protocol) DeleteContact(contact device.ContactID) {
	proto.application.DeleteContact(contact)
}

// SyncAddMessage will add a message to a synchronized group.
// If attachedContact is not nil, the shared secret for the given contact will be attached to the message and shared in the group,
// in order for other group members to join the the attached group.
//
// The synchronization protocol option must be enabled in order to use this method.
func (proto *Protocol) SyncAddMessage(contact device.ContactID, message []byte, attachedContact *device.ContactID) error {
	proto.log("sync_add_message")
	return proto.application.SyncAddMessage(contact, message, attachedContact)
}

func (proto *Protocol) SyncLoadState(contact device.ContactID, state []byte) error {
	return proto.application.SyncLoadState(contact, state)
}

func (proto *Protocol) JoinGroup(groupSecret device.SharedSecret) (device.ContactID, error) {
	proto.log("join_group")
	return proto.application.JoinGroup(groupSecret)
}
