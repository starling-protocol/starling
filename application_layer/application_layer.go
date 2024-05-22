package application_layer

import (
	"crypto/ed25519"
	"fmt"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/sync"
	"github.com/starling-protocol/starling/transport_layer"
)

type pendingSyncPushPacket struct {
	contact device.ContactID
	session device.SessionID
	packet  *sync.PushPacket
}

func newPendingSyncPushPacket(contact device.ContactID, session device.SessionID, packet *sync.PushPacket) pendingSyncPushPacket {
	return pendingSyncPushPacket{
		contact: contact,
		session: session,
		packet:  packet,
	}
}

type ApplicationLayer struct {
	dev                    device.Device
	options                device.ProtocolOptions
	transportLayer         *transport_layer.TransportLayer
	sync                   *sync.Sync
	pendingSyncPushPackets map[device.MessageID]pendingSyncPushPacket
}

func NewApplicationLayer(dev device.Device, options device.ProtocolOptions) *ApplicationLayer {
	app := ApplicationLayer{
		dev:                    dev,
		options:                options,
		transportLayer:         nil,
		sync:                   nil,
		pendingSyncPushPackets: make(map[device.MessageID]pendingSyncPushPacket),
	}

	if options.EnableSync {
		syncEvents := syncEvents{app: &app}
		app.sync = sync.NewSync(&syncEvents)
	}

	transportEvents := transportEvents{app: &app}
	app.transportLayer = transport_layer.NewTransportLayer(dev, &transportEvents, options)
	return &app
}

func (app *ApplicationLayer) LoadPersistedState() {
	if app.options.EnableSync {
		for _, group := range app.dev.ContactsContainer().AllGroups() {
			if app.sync.HasContact(group) {
				continue
			}

			_, privateKey, err := ed25519.GenerateKey(app.dev.CryptoRand())
			if err != nil {
				app.logf("Failed to generate private key for group: %v", err)
				continue
			}
			app.sync.NewContact(group, privateKey, sync.ModelTypeGroup)
		}

		for _, link := range app.dev.ContactsContainer().AllLinks() {
			if app.sync.HasContact(link) {
				continue
			}

			_, privateKey, err := ed25519.GenerateKey(app.dev.CryptoRand())
			if err != nil {
				app.logf("Failed to generate private key for link: %v", err)
				continue
			}
			app.sync.NewContact(link, privateKey, sync.ModelTypeLink)
		}
	}
}

func (app *ApplicationLayer) log(body ...any) {
	app.dev.Log(fmt.Sprintf("application:%s", fmt.Sprint(body...)))
}

func (app *ApplicationLayer) logf(msg string, args ...any) {
	app.log(fmt.Sprintf(msg, args...))
}

func (app *ApplicationLayer) OnConnection(address device.DeviceAddress) {
	app.transportLayer.OnConnection(address)
}

func (app *ApplicationLayer) OnDisconnection(address device.DeviceAddress) {
	app.transportLayer.OnDisconnection(address)
}

func (app *ApplicationLayer) SendMessage(session device.SessionID, message []byte) (device.MessageID, error) {
	data := append([]byte{0x01}, message...) // 0x01 user data extension
	return app.transportLayer.SendMessage(session, data)
}

func (app *ApplicationLayer) BroadcastRouteRequest() {
	app.transportLayer.BroadcastRouteRequest()
}

func (app *ApplicationLayer) ReceivePacket(address device.DeviceAddress, packet []byte) {
	messages := app.transportLayer.ReceivePacket(address, packet)
	for _, message := range messages {
		app.handlePacket(message.Session, message.Contact, message.Data)
	}
}

func (app *ApplicationLayer) handlePacket(session device.SessionID, contact device.ContactID, packet []byte) {
	if len(packet) == 0 {
		return
	}

	switch packet[0] {
	case 0x01: // user data
		app.logf("handle_packet:user_data:%d", session)
		app.dev.ProcessMessage(session, packet[1:])
	case 0x02: // sync extension
		app.logf("handle_packet:sync:%d:%s", session, contact)
		app.handleSyncPacket(session, contact, packet)
	default: // unknown
		app.logf("handle_packet:error:unknown_packet_type:%d:%s:%d", session, contact, packet[0])
	}
}

func (app *ApplicationLayer) ContactCreated(contact device.ContactID, modelType sync.ModelType) error {
	if app.options.EnableSync {
		_, priv, err := ed25519.GenerateKey(app.dev.CryptoRand())
		if err != nil {
			app.logf("new_contact:error '%v'", err)
			return err
		}

		if err := app.sync.NewContact(contact, priv, modelType); err != nil {
			app.logf("new_contact:error '%v'", err)
			return err
		}
	}

	return nil
}

func (app *ApplicationLayer) JoinGroup(groupSecret device.SharedSecret) (device.ContactID, error) {
	contact, err := app.dev.ContactsContainer().JoinGroup(groupSecret)
	if err != nil {
		app.logf("new_contact:error '%v'", err)
		return "", err
	}

	if err := app.ContactCreated(contact, sync.ModelTypeGroup); err != nil {
		return "", err
	}

	// Broadcast route request to discover members of the group
	app.BroadcastRouteRequest()

	return contact, nil
}

func (app *ApplicationLayer) DeleteContact(contact device.ContactID) {
	app.transportLayer.DeleteContact(contact)

	if app.options.EnableSync {
		app.sync.DeleteContact(contact)
		app.dev.SyncStateChanged(contact, nil)
	}
}
