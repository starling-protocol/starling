package device

import (
	"io"
	"math/rand"
	"time"
)

// A DeviceAddress represents an address of a locally connected peer
type DeviceAddress string

// The SharedSecret is used to derive a device.ContactID and is used to encrypt messages
type SharedSecret []byte

// A ContactID identifies a contact
type ContactID string

// The ContactMap maps the local contacts to their respective secrets in order to encrypt and decrypt messages
// type ContactMap map[ContactID]SharedSecret

// A MessageID is generated when sending a message in order to later get notified if it has been delivered
type MessageID uint64

// A SessionID is used to identify a network layer session
type SessionID uint64

type ProtocolOptions struct {
	// EnableSync determines whether the sync extension is enabled.
	EnableSync bool
	// When DisableAutoRREQOnConnection is activated, nodes will not automatically send route requests on connection.
	DisableAutoRREQOnConnection bool
	// The max time to live to give a packet when broadcasting or forwarding route requests.
	MaxRREQTTL int
	// RREQBroadcastStrategy determines what strategy to use when forwarding route requests.
	RREQBroadcastStrategy BroadcastStrategy
	// Whether or not to forward route requests, even when the node identifies that it is included in the bitmap.
	ForwardRREQsWhenMatching bool
	// ACKDelay
	ACKDelay time.Duration
	// ACKTimeout
	ACKTimeout time.Duration

	// Proposed:
	// * RREQ throttling
	// * Different priorities when encoding bitmap for route requests
}

type BroadcastStrategy int

const (
	// Forwards route requests to all connected peers.
	BroadcastAll BroadcastStrategy = iota
	// Forwards route requests to a random sample of the connected peers
	// with the number of forwards determined by a logarithmic function.
	BroadcastLogFunc
	// Forwards route requests to two randomly selected peers.
	BroadcastTwo
)

func DefaultProtocolOptions() *ProtocolOptions {
	return &ProtocolOptions{
		EnableSync:                  false,
		DisableAutoRREQOnConnection: false,
		MaxRREQTTL:                  10,
		RREQBroadcastStrategy:       BroadcastAll,
		ForwardRREQsWhenMatching:    false,
		ACKDelay:                    1 * time.Second,
		ACKTimeout:                  3 * time.Second,
	}
}

func DefaultSyncProtocolOptions() *ProtocolOptions {
	protocolOptions := DefaultProtocolOptions()
	protocolOptions.EnableSync = true
	return protocolOptions
}

// The device that the protocol uses to interact with the environment.
type Device interface {
	// Log prints a message to the device log.
	Log(message string)
	// SendPacket sends a packet to the device with the provided address.
	SendPacket(address DeviceAddress, packet []byte)
	// MessageDelivered is called when a message has been confirmed to have been received.
	MessageDelivered(messageID MessageID)
	// MaxPacketSize returns the max packet size for some peer given by its address.
	MaxPacketSize(address DeviceAddress) (int, error)
	// ProcessMessage is called when packet(s) from a peer have been decoded to a message
	ProcessMessage(session SessionID, message []byte)
	// ReplyPayload is called when a matching route request is received.
	// It returns the payload that should be included with the route reply.
	ReplyPayload(session SessionID, contact ContactID) []byte
	// SessionEstablished is called when a new session with the given contact has been established
	SessionEstablished(session SessionID, contact ContactID, address DeviceAddress)
	// SessionBroken is called when a previously established session has been broken
	// and is no longer available
	SessionBroken(session SessionID)
	// SyncStateChanged is called whenever the synchronization state changes for a given contact.
	// The state is encoded as JSON.
	// This event is only called when the sync option is turned on.
	SyncStateChanged(contact ContactID, stateUpdate []byte)
	// Rand is used for generating all random values, a default is used when nil is returned
	Rand() *rand.Rand
	// CryptoRand should produce cryptographically secure random bytes in production
	CryptoRand() io.Reader
	// Delay performs the given action after the duration has passed
	Delay(action func(), duration time.Duration)
	// Now returns the current time of the device
	Now() time.Time

	ContactsContainer() ContactsContainer
}
