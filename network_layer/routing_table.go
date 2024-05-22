package network_layer

import (
	"crypto/ecdh"
	"encoding/binary"
	"math/rand"

	"github.com/starling-protocol/starling/device"
)

type RequestID uint64

type RequestTable map[RequestID]*RequestTableEntry
type SessionTable map[device.SessionID]*SessionTableEntry

func EncodeSessionID(session device.SessionID, buf []byte) []byte {
	return binary.BigEndian.AppendUint64(buf, uint64(session))
}

func (r RequestID) Encode(buf []byte) []byte {
	return binary.BigEndian.AppendUint64(buf, uint64(r))
}

func DecodeSessionID(buf []byte) device.SessionID {
	return device.SessionID(binary.BigEndian.Uint64(buf))
}

func DecodeRequestID(buf []byte) RequestID {
	return RequestID(binary.BigEndian.Uint64(buf))
}

type RequestTableEntry struct {
	RequestID           RequestID
	SourceNeighbour     *device.DeviceAddress
	EphemeralPrivateKey *ecdh.PrivateKey
}

func NewRequestTableEntry(reqID RequestID, source *device.DeviceAddress, ephemeral *ecdh.PrivateKey) RequestTableEntry {
	return RequestTableEntry{
		RequestID:           reqID,
		SourceNeighbour:     source,
		EphemeralPrivateKey: ephemeral,
	}
}

type SessionTableEntry struct {
	RequestID       RequestID
	SessionID       device.SessionID
	Contact         *device.ContactID
	SourceNeighbour *device.DeviceAddress
	TargetNeighbour *device.DeviceAddress
	SessionSecret   []byte
}

func (s *SessionTableEntry) EndpointSession() bool {
	return s.Contact != nil
}

func SessionEntryFromRREQ(random *rand.Rand, contact *device.ContactID, reqEntry RequestTableEntry, sender *device.DeviceAddress, sessionSecret []byte) SessionTableEntry {
	return SessionTableEntry{
		RequestID:       reqEntry.RequestID,
		SessionID:       device.SessionID(random.Int63()),
		Contact:         contact,
		SourceNeighbour: sender,
		TargetNeighbour: nil,
		SessionSecret:   sessionSecret,
	}
}

func SessionEntryFromRREP(random *rand.Rand, contact *device.ContactID, reqEntry RequestTableEntry, rrep RREPPacket, sender *device.DeviceAddress, sessionSecret []byte) SessionTableEntry {
	return SessionTableEntry{
		RequestID:       reqEntry.RequestID,
		SessionID:       rrep.SessionID,
		Contact:         contact,
		SourceNeighbour: reqEntry.SourceNeighbour,
		TargetNeighbour: sender,
		SessionSecret:   sessionSecret,
	}
}
