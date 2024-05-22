package network_layer

import (
	"crypto/ecdh"
	"crypto/sha256"
	"errors"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/utils"

	"golang.org/x/crypto/hkdf"
)

func SessionSecret(container device.ContactsContainer, contact device.ContactID, ephemeral []byte, remoteEphemeral []byte) (device.SharedSecret, error) {
	contactSecret, err := container.ContactSecret(contact)
	if err != nil {
		return nil, err
	}

	ephemeralKey, err := ecdh.X25519().NewPrivateKey(ephemeral)
	if err != nil {
		return nil, err
	}

	remoteEphemeralKey, err := ecdh.X25519().NewPublicKey(remoteEphemeral)
	if err != nil {
		return nil, err
	}

	ephemeralSecret, err := ephemeralKey.ECDH(remoteEphemeralKey)
	if err != nil {
		return nil, err
	}

	secret := append(contactSecret, ephemeralSecret...)
	reader := hkdf.New(sha256.New, secret, nil, nil)

	var sessionSecret [32]byte
	n, err := reader.Read(sessionSecret[:])
	if err != nil {
		return nil, err
	}
	if n != 32 {
		return nil, errors.New("failed to read 32 bytes session secret")
	}

	return sessionSecret[:], nil
}

func (network *NetworkLayer) GetSession(sessionID device.SessionID) (*SessionTableEntry, bool) {
	sess, found := network.sessionTable[sessionID]
	return sess, found
}

func (network *NetworkLayer) AllSessions(contact device.ContactID) []device.SessionID {
	random := network.dev.Rand()
	sessions := []device.SessionID{}
	for _, sessionID := range utils.ShuffleMapKeys(random, network.sessionTable) {
		session := network.sessionTable[sessionID]
		if session.Contact != nil && *session.Contact == contact {
			sessions = append(sessions, session.SessionID)
		}
	}
	return sessions
}

func (network *NetworkLayer) SessionEstablished(contact device.ContactID, session device.SessionID, address device.DeviceAddress, payload []byte, isInitiator bool) {
	network.logf("session:established:%s:%d", contact, session)
	network.events.SessionEstablished(session, contact, address, payload, isInitiator)
}

func (network *NetworkLayer) SessionBroken(sessID device.SessionID, address *device.DeviceAddress) {
	if _, found := network.sessionTable[sessID]; !found {
		return
	}

	network.logf("session:broken:%d", sessID)

	if address == nil {
		// Session broken due to timeout. Send RERR
		sessionTableEntry := network.sessionTable[sessID]
		if sessionTableEntry != nil {
			if sessionTableEntry.SourceNeighbour != nil {
				network.sendRouteError(*sessionTableEntry.SourceNeighbour, sessID)
			} else if sessionTableEntry.TargetNeighbour != nil {
				network.sendRouteError(*sessionTableEntry.TargetNeighbour, sessID)
			}
		}
	}

	isEndpointSession := network.sessionTable[sessID].EndpointSession()
	delete(network.sessionTable, sessID)

	if isEndpointSession {
		network.events.SessionBroken(sessID)
	}
}
