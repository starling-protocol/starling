package sync

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/starling-protocol/starling/device"
)

type SyncEvents interface {
	PushSyncUpdates(contact device.ContactID, session device.SessionID, pushPacket *PushPacket)
	// DiscoverContact is called when there is an update to a contact with no currently active session.
	// A route request may be broadcasted in order to deliver the update if possible.
	DiscoverContact(contact device.ContactID)
	SyncStateChanged(contact device.ContactID, updatedState []byte)
	Log(message string)
}

type syncSession struct {
	contact   device.ContactID
	publicKey NodePublicKey
	// receivePull is set to true when a PULL packet is received from the publicKey,
	// when false only a PUSH packet has been received, and the session should be ignored until a PULL packet is received.
	receivePull bool
}

type Sync struct {
	state    map[device.ContactID]*Model
	events   SyncEvents
	sessions map[device.SessionID]syncSession
}

func NewSync(events SyncEvents) *Sync {
	return &Sync{
		state:    map[device.ContactID]*Model{},
		events:   events,
		sessions: map[device.SessionID]syncSession{},
	}
}

func (sync *Sync) log(body ...any) {
	sync.events.Log(fmt.Sprintf("sync:%s", fmt.Sprint(body...)))
}

func (sync *Sync) logf(msg string, args ...any) {
	sync.log(fmt.Sprintf(msg, args...))
}

func (sync *Sync) LoadState(contact device.ContactID, state []byte) error {
	model, err := DecodeModelFromJSON(state)
	if err != nil {
		return err
	}

	sync.logf("state:load:%d", len(model.NodeStates))

	sync.state[contact] = model

	updatedState, err := sync.ContactState(contact)
	if err != nil {
		return err
	}
	sync.events.SyncStateChanged(contact, updatedState)

	return nil
}

func (sync *Sync) ContactState(contact device.ContactID) ([]byte, error) {
	return sync.state[contact].EncodeToJSON()
}

func (sync *Sync) NewContact(contact device.ContactID, privateKey ed25519.PrivateKey, modelType ModelType) error {
	sync.logf("new_contact:%s:%s", modelType, contact)

	sync.state[contact] = NewModel(privateKey, modelType)

	if err := sync.notifyStateChanges(contact); err != nil {
		return err
	}

	return nil
}

func (sync *Sync) DeleteContact(contact device.ContactID) {
	sync.logf("delete_contact:%s", contact)
	delete(sync.state, contact)
}

func (sync *Sync) HasContact(contact device.ContactID) bool {
	_, found := sync.state[contact]
	return found
}

func (sync *Sync) updateSyncSession(session device.SessionID, contact device.ContactID, publicKey NodePublicKey, receivePull bool) {
	pullValue := receivePull
	if _, found := sync.sessions[session]; found {
		pullValue = pullValue || sync.sessions[session].receivePull
	}

	sync.sessions[session] = syncSession{
		contact:     contact,
		publicKey:   publicKey,
		receivePull: pullValue,
	}

	sync.logf("update_sync_session:%d:%v", session, receivePull)
}

func (sync *Sync) SessionBroken(session device.SessionID) {
	sync.logf("session_broken:%d", session)
	delete(sync.sessions, session)
}

// Notify locally that state has changed.
func (sync *Sync) notifyStateChanges(contact device.ContactID) error {
	newState, err := sync.ContactState(contact)
	if err != nil {
		return err
	}
	sync.events.SyncStateChanged(contact, newState)
	return nil
}

// pushStateUpdates checks if all sessions are up to date
// and send PushSyncUpdates events to all outdated sessions.
func (sync *Sync) pushStateUpdates(contact device.ContactID) error {
	contactState, found := sync.state[contact]
	if !found {
		return errors.New("error pushing state updates 'contact not found'")
	}

	shouldDiscoverContact := true

	// look for outdated sessions and send push events
	for session, identity := range sync.sessions {
		if identity.contact != contact {
			continue
		}

		shouldDiscoverContact = false

		// if we have only received a PULL packet on this session (thus not received a digest)
		// then we should wait for a PULL before proactively sending a PUSH.
		if !identity.receivePull {
			continue
		}

		sessionDigest := contactState.Digests[identity.publicKey]
		delta := contactState.Delta(sessionDigest)

		if len(delta) > 0 {
			sync.logf("sync_update:push:%d:%d", session, len(delta))
			replyPushPacket := contactState.NewPushPacket(identity.publicKey, delta)
			sync.events.PushSyncUpdates(contact, session, replyPushPacket)
		}
	}

	if shouldDiscoverContact {
		sync.events.DiscoverContact(contact)
	}

	return nil
}

func (sync *Sync) NewMessage(contact device.ContactID, body []byte, attachedSecret device.SharedSecret) error {
	sync.logf("new_message:%s", contact)
	body = bytes.Clone(body)

	contactState, found := sync.state[contact]
	if !found {
		return errors.New("error updating node digest 'contact not found'")
	}

	contactState.NewMessage(body, attachedSecret)

	if err := sync.notifyStateChanges(contact); err != nil {
		return err
	}

	if err := sync.pushStateUpdates(contact); err != nil {
		return err
	}

	return nil
}

func (sync *Sync) MergePushPacket(session device.SessionID, contact device.ContactID, pushPacket *PushPacket) error {
	sync.logf("packet:push:merge:%s:%d", contact, session)

	contactState, found := sync.state[contact]
	if !found {
		return errors.New("state for contact not found")
	}

	sync.updateSyncSession(session, contact, pushPacket.senderPublicKey, false)

	stateChanged := contactState.Merge(pushPacket.senderPublicKey, pushPacket.delta)
	if !stateChanged {
		return nil
	}

	sync.log("packet:push:merge:state_change")

	if err := sync.notifyStateChanges(contact); err != nil {
		return err
	}

	if err := sync.pushStateUpdates(contact); err != nil {
		return fmt.Errorf("error merging delta: %w", err)
	}

	return nil
}

// HandlePullPacket is called in a response to a pull packet
func (sync *Sync) HandlePullPacket(session device.SessionID, contact device.ContactID, publicKey NodePublicKey, digest *Digest) error {
	sync.logf("packet:pull:handle:%s:%d", contact, session)

	contactState, found := sync.state[contact]
	if !found {
		return errors.New("error updating node digest 'contact not found'")
	}

	sync.updateSyncSession(session, contact, publicKey, true)

	digestUpdated := contactState.UpdateDigests(publicKey, digest)

	if digestUpdated {
		sync.log("packet:pull:handle:digest_updated")
		if err := sync.notifyStateChanges(contact); err != nil {
			return err
		}
	}

	sessionDigest := contactState.Digests[publicKey]
	delta := contactState.Delta(sessionDigest)

	if len(delta) > 0 {
		sync.logf("packet:pull:handle:push_reply:%d", len(delta))
		replyPushPacket := contactState.NewPushPacket(publicKey, delta)
		sync.events.PushSyncUpdates(contact, session, replyPushPacket)
	}

	return nil
}

func (sync *Sync) PullPacket(contact device.ContactID) (*PullPacket, error) {
	return sync.state[contact].NewPullPacket()
}
