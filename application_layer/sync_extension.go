package application_layer

import (
	"fmt"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/sync"
)

type ConnectionState map[device.SessionID]sync.NodePublicKey

type syncEvents struct {
	app *ApplicationLayer
}

// Log implements sync.SyncEvents.
func (sync *syncEvents) Log(message string) {
	sync.app.log(message)
}

// PushSyncUpdates implements sync.SyncEvents.
func (sync *syncEvents) PushSyncUpdates(contact device.ContactID, session device.SessionID, pushPacket *sync.PushPacket) {
	sync.app.logf("sync:push_sync_updates:%s", contact)

	data := pushPacket.Encode()
	data = append([]byte{0x02}, data...)

	msgID, err := sync.app.transportLayer.SendMessage(session, data)
	if err != nil {
		sync.app.logf("sync:push_sync_updates:send:error '%v'", err)
		return
	}

	sync.app.pendingSyncPushPackets[msgID] = newPendingSyncPushPacket(contact, session, pushPacket)
}

// SyncStateChanged implements sync.SyncEvents.
func (sync *syncEvents) SyncStateChanged(contact device.ContactID, updatedState []byte) {
	sync.app.dev.SyncStateChanged(contact, updatedState)
}

// DiscoverContact implements sync.SyncEvents.
func (sync *syncEvents) DiscoverContact(contact device.ContactID) {
	sync.app.logf("sync:discover_contact:%s", contact)
	sync.app.BroadcastRouteRequest()
}

func (app *ApplicationLayer) handleSyncPacket(session device.SessionID, contact device.ContactID, packet []byte) {
	err := app.sync.ReceiveSyncPacket(contact, session, packet[1:])
	if err != nil {
		app.logf("handle_packet:sync:error '%v'", err)
		return
	}
}

func (app *ApplicationLayer) SyncAddMessage(contact device.ContactID, message []byte, attachedContact *device.ContactID) error {
	app.log("sync_add_message")

	if !app.options.EnableSync {
		panic("sync_add_message:error 'synchronization is not enabled'")
	}

	var attachedSecret device.SharedSecret = nil
	if attachedContact != nil {
		var err error
		attachedSecret, err = app.dev.ContactsContainer().ContactSecret(*attachedContact)
		if err != nil {
			return fmt.Errorf("attachedContact secret not found in contact map: %w", err)
		}
	}

	err := app.sync.NewMessage(contact, message, attachedSecret)
	if err != nil {
		return fmt.Errorf("sync add message error: %w", err)
	}

	return nil
}

func (app *ApplicationLayer) SyncLoadState(contact device.ContactID, state []byte) error {
	app.log("sync_load_state")
	if !app.options.EnableSync {
		panic("sync_load_state:error 'synchronization is not enabled'")
	}

	return app.sync.LoadState(contact, state)
}
