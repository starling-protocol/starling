package network_layer

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/network_layer/contact_bitmap"
	"github.com/starling-protocol/starling/utils"
)

type TTL uint16
type PublicKey int64

func (ttl TTL) Encode(buf []byte) []byte {
	return binary.BigEndian.AppendUint16(buf, uint16(ttl))
}

func DecodeTTL(buf []byte) TTL {
	return TTL(binary.BigEndian.Uint16(buf))
}

type RREQPacket struct {
	RequestID    RequestID
	TTL          TTL
	EphemeralKey ecdh.PublicKey
	ContactMask  contact_bitmap.ContactBitmap
}

func NewRREQPacket(reqID RequestID, ttl TTL, ephemeralKey ecdh.PublicKey, contactMap contact_bitmap.ContactBitmap) *RREQPacket {
	if len(contactMap) != contact_bitmap.BITMAP_SIZE {
		panic("size of contactMap argument was wrong")
	}

	return &RREQPacket{
		RequestID:    reqID,
		TTL:          ttl,
		EphemeralKey: ephemeralKey,
		ContactMask:  contactMap,
	}
}

func (*RREQPacket) PacketType() PacketType {
	return RREQ
}

func (packet *RREQPacket) EncodePacket() []byte {
	buf := []byte{}
	buf = append(buf, byte(RREQ))
	buf = packet.RequestID.Encode(buf)
	buf = packet.TTL.Encode(buf)
	buf = append(buf, packet.EphemeralKey.Bytes()...)
	buf = append(buf, packet.ContactMask...)
	return buf
}

func DecodeRREQ(buf []byte) (*RREQPacket, error) {
	if len(buf) < 43+contact_bitmap.BITMAP_SIZE {
		return nil, fmt.Errorf("buffer too small when decoding RREQ: %d", len(buf))
	}

	if buf[0] != byte(RREQ) {
		return nil, fmt.Errorf("wrong packet header when decoding RREQ packet: %d", buf[0])
	}

	reqID := DecodeRequestID(buf[1:])
	ttl := DecodeTTL(buf[9:])

	ephemeralKey, err := ecdh.X25519().NewPublicKey(buf[11:43])
	if err != nil {
		return nil, err
	}

	contactMap := buf[43 : 43+contact_bitmap.BITMAP_SIZE]

	return NewRREQPacket(reqID, ttl, *ephemeralKey, contactMap), nil
}

func (network *NetworkLayer) BroadcastRouteRequest() {
	ttl := TTL(network.options.MaxRREQTTL)
	rreqPacket, err := network.buildRouteRequest(ttl)
	if err != nil {
		network.logf("packet:rreq:broadcast:error '%v'", err)
		return
	}

	network.log("packet:rreq:broadcast 'broadcasting rreq packet'")
	network.packetLayer.BroadcastBytes(rreqPacket.EncodePacket())
}

func (network *NetworkLayer) SendRouteRequest(address device.DeviceAddress, ttl TTL) {
	rreqPacket, err := network.buildRouteRequest(ttl)
	if err != nil {
		network.logf("packet:rreq:send:error '%v'", err)
		return
	}

	network.logf("packet:rreq:send:%s", address)
	network.packetLayer.SendBytes(address, rreqPacket.EncodePacket())
}

func (network *NetworkLayer) handleRouteRequest(rreq RREQPacket, sender device.DeviceAddress) {
	// TODO: Check if we are receiving too many RREQs, and should throttle

	// Check if we have seen this RREQ before
	_, hasSeenRequestID := network.requestTable[rreq.RequestID]
	if hasSeenRequestID {
		network.logf("packet:rreq:duplicate:%s:%d", sender, rreq.RequestID)
		return
	}

	network.logf("packet:rreq:receive:%s:%d", sender, rreq.RequestID)

	// Create table entry
	networkTableEntry := &RequestTableEntry{
		RequestID:       rreq.RequestID,
		SourceNeighbour: &sender,
	}
	network.requestTable[rreq.RequestID] = networkTableEntry

	// Check if we are recipient
	decodedContacts, err := contact_bitmap.DecodeContactBitmap(network.dev.Rand(), network.dev.ContactsContainer(), contact_bitmap.Seed(rreq.RequestID), rreq.ContactMask)
	if err != nil {
		network.logf("packet:rreq:error '%v'", err)
		return
	}

	if len(decodedContacts) == 0 {
		network.forwardRouteRequest(rreq, sender)
		return
	}

	// We are a recipient and thus reply with a RREP
	for _, contactID := range decodedContacts {
		// Create session
		random := network.dev.Rand()

		request := network.requestTable[rreq.RequestID]

		ephemeralPrivate, err := ecdh.X25519().GenerateKey(network.dev.CryptoRand())
		if err != nil {
			network.logf("packet:rreq:build_reply:error '%v'", err)
			return
		}

		sessionSecret, err := SessionSecret(network.dev.ContactsContainer(), contactID, ephemeralPrivate.Bytes(), rreq.EphemeralKey.Bytes())
		if err != nil {
			network.logf("packet:rreq:build_reply:error '%v'", err)
			return
		}

		sessionEntry := SessionEntryFromRREQ(random, &contactID, *request, &sender, sessionSecret)
		sessionID := sessionEntry.SessionID
		network.sessionTable[sessionID] = &sessionEntry

		network.SessionEstablished(contactID, sessionID, sender, nil, false)

		payload := network.events.ReplyPayload(sessionID, contactID)

		rrep, err := network.NewRREP(
			rreq.RequestID,
			sessionID,
			sessionSecret,
			*ephemeralPrivate.PublicKey(),
			payload,
		)
		if err != nil {
			network.logf("packet:rreq:build_reply:error '%v'", err)
			continue
		}

		network.logf("packet:rreq:contact_match:%s:%d 'found known contact in rreq'", contactID, rreq.TTL)

		network.forwardRouteReply(*rrep, &sessionEntry)

		if network.options.ForwardRREQsWhenMatching {
			network.forwardRouteRequest(rreq, sender)
		}
	}
}

func (network *NetworkLayer) forwardRouteRequest(rreq RREQPacket, sender device.DeviceAddress) {
	if rreq.TTL > TTL(network.options.MaxRREQTTL) {
		rreq.TTL = TTL(network.options.MaxRREQTTL)
	}

	// We are not recipient, and thus forward the rreq if TTL is not 0
	rreq.TTL -= 1
	if rreq.TTL <= 0 {
		network.log("packet:rreq:ttl_expired")
		return
	}

	network.logf("packet:rreq:forward:%d:%d", rreq.RequestID, rreq.TTL)
	network.BroadcastPacketExcept(&rreq, sender)
}

// Builds a new RREQ packet based on the current state of the network layer
func (network *NetworkLayer) buildRouteRequest(ttl TTL) (*RREQPacket, error) {
	cryptoRand := network.dev.CryptoRand()
	random := network.dev.Rand()

	allContacts := network.dev.ContactsContainer().AllGroups()
	allContacts = append(allContacts, network.dev.ContactsContainer().AllLinks()...)

	prioritizedContacts := []device.ContactID{}
	for _, contact := range allContacts {
		// TODO: Actually prioritize contacts
		hasSession := false

		for _, sessionID := range utils.ShuffleMapKeys(random, network.sessionTable) {
			session := network.sessionTable[sessionID]
			if session.Contact != nil && contact == *session.Contact {
				hasSession = true
				break
			}
		}

		if !hasSession {
			prioritizedContacts = append(prioritizedContacts, contact)
		}
	}

	bitmapResult, err := contact_bitmap.EncodeContactBitmap(cryptoRand, prioritizedContacts, network.dev.ContactsContainer(), 5)
	if err != nil {
		return nil, err
	}

	if bitmapResult.ContactCount == 0 {
		network.logf("packet:rreq:build:no_contacts:%d:%d", len(allContacts), len(network.sessionTable))
		return nil, errors.New("no contacts encoded in route request")
	}

	requestID := RequestID(bitmapResult.Seed)
	ephemeralPrivate, err := ecdh.X25519().GenerateKey(cryptoRand)
	if err != nil {
		return nil, err
	}

	requestTableEntry := NewRequestTableEntry(requestID, nil, ephemeralPrivate)
	network.requestTable[requestID] = &requestTableEntry

	network.logf("packet:rreq:build:%d:%d:%d:%d", bitmapResult.ContactCount, len(allContacts), ttl, requestID)

	rreq := NewRREQPacket(requestID, ttl, *ephemeralPrivate.PublicKey(), bitmapResult.Bitmap)
	return rreq, nil
}
