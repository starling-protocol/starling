package network_layer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/binary"
	"fmt"

	"github.com/starling-protocol/starling/device"
)

type RREPPacket struct {
	RequestID    RequestID
	SessionID    device.SessionID
	EphemeralKey ecdh.PublicKey
	Nonce        []byte
	// Cipher contains the authentication tag as well as some optional payload
	Cipher []byte
}

func EncodeRREPHeader(reqID RequestID, sessID device.SessionID, ephemeralKey ecdh.PublicKey) []byte {
	buf := []byte{byte(RREP)}
	buf = reqID.Encode(buf)
	buf = EncodeSessionID(sessID, buf)
	buf = append(buf, ephemeralKey.Bytes()...)
	return buf
}

func (network *NetworkLayer) NewRREP(reqID RequestID, sessID device.SessionID, sessionSecret []byte, ownEphemeralPublicKey ecdh.PublicKey, payload []byte) (*RREPPacket, error) {
	cryptoRand := network.dev.CryptoRand()

	nonce := make([]byte, 12)
	if _, err := cryptoRand.Read(nonce); err != nil {
		return nil, err
	}

	aesCipher, err := aes.NewCipher(sessionSecret)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	headers := EncodeRREPHeader(reqID, sessID, ownEphemeralPublicKey)
	cipher := aesgcm.Seal(nil, nonce, payload, headers)

	return &RREPPacket{
		RequestID:    reqID,
		SessionID:    sessID,
		EphemeralKey: ownEphemeralPublicKey,
		Nonce:        nonce,
		Cipher:       cipher,
	}, nil
}

// func (routing *NetworkLayer) ComputeSessionFromEphemerals(contact device.ContactID, otherEphemeralPublicKey ecdh.PublicKey, ownEphemeralPrivateKey *ecdh.PrivateKey) ([]byte, error) {
// 	ephemeralSecret, err := ownEphemeralPrivateKey.ECDH(&otherEphemeralPublicKey)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return routing.ComputeSessionSecret(contact, ephemeralSecret)
// }

// func (network *NetworkLayer) ComputeSessionSecret(contact device.ContactID, ephemeralSecret []byte) ([]byte, error) {
// 	secret, found := network.contacts[contact]
// 	if !found {
// 		return nil, errors.New("could not find contact in contactlist")
// 	}
// 	secret = append(secret, ephemeralSecret...)
// 	reader := hkdf.New(sha256.New, secret, nil, nil)

// 	var sessionSecret [32]byte
// 	n, err := reader.Read(sessionSecret[:])
// 	if err != nil {
// 		return nil, err
// 	}
// 	if n != 32 {
// 		return nil, errors.New("failed to read 32 bytes session secret")
// 	}

// 	return sessionSecret[:], nil
// }

func (p *RREPPacket) PacketType() PacketType {
	return RREP
}

func (p *RREPPacket) EncodePacket() []byte {
	buf := EncodeRREPHeader(p.RequestID, p.SessionID, p.EphemeralKey)
	buf = append(buf, p.Nonce...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(p.Cipher)-16))
	buf = append(buf, p.Cipher...)

	return buf
}

func DecodeRREP(buf []byte) (*RREPPacket, error) {
	if len(buf) < 65 {
		return nil, fmt.Errorf("buffer too small when decoding RREP: %d", len(buf))
	}

	if buf[0] != byte(RREP) {
		return nil, fmt.Errorf("wrong packet header when decoding RREP packet: %d", buf[0])
	}

	reqID := DecodeRequestID(buf[1:])
	sessID := DecodeSessionID(buf[9:])
	ephemeralKey, err := ecdh.X25519().NewPublicKey(buf[17:49])
	if err != nil {
		return nil, err
	}
	nonce := buf[49:61]
	payloadSize := binary.BigEndian.Uint32(buf[61:65])
	if len(buf) < 65+int(payloadSize)+16 {
		return nil, fmt.Errorf("buffer too small to decode RREP payload of size %d bytes: %d", payloadSize, len(buf))
	}

	cipher := buf[65 : 65+payloadSize+16]

	return &RREPPacket{
		RequestID:    reqID,
		SessionID:    sessID,
		EphemeralKey: *ephemeralKey,
		Nonce:        nonce,
		Cipher:       cipher,
	}, nil
}

func (network *NetworkLayer) forwardRouteReply(rrep RREPPacket, session *SessionTableEntry) {
	network.logf("packet:rrep:forward:%s", *session.SourceNeighbour)
	successful := network.packetLayer.SendBytes(*session.SourceNeighbour, rrep.EncodePacket())
	if !successful {
		if session.TargetNeighbour != nil {
			network.sendRouteError(*session.TargetNeighbour, session.SessionID)
		}
		network.SessionBroken(session.SessionID, session.SourceNeighbour)
	}
}

func (network *NetworkLayer) handleRouteReply(rrep RREPPacket, sender device.DeviceAddress) {
	random := network.dev.Rand()

	request, reqFound := network.requestTable[rrep.RequestID]
	if !reqFound {
		network.logf("Received unknown route reply with request id: %v", rrep.RequestID)
		return
	}

	network.logf("packet:rrep:receive:%s", sender)

	if request.SourceNeighbour == nil {

		headers := EncodeRREPHeader(rrep.RequestID, rrep.SessionID, rrep.EphemeralKey)

		// Precompute ephemeral secret
		// ephemeralSecret, err := request.EphemeralPrivateKey.ECDH(&rrep.EphemeralKey)
		// if err != nil {
		// 	network.logf("packet:rrep:compute_session_secret:error '%v'", err)
		// 	return
		// }

		contacts := network.dev.ContactsContainer().AllLinks()
		contacts = append(contacts, network.dev.ContactsContainer().AllGroups()...)

		for _, contact := range contacts {
			sessionSecret, err := SessionSecret(network.dev.ContactsContainer(), contact, request.EphemeralPrivateKey.Bytes(), rrep.EphemeralKey.Bytes())
			if err != nil {
				network.logf("packet:rrep:compute_session_secret:error '%v'", err)
				return
			}

			aesCipher, err := aes.NewCipher(sessionSecret)
			if err != nil {
				network.logf("packet:rrep:cipher:error '%v'", err)
				return
			}

			aesgcm, err := cipher.NewGCM(aesCipher)
			if err != nil {
				network.logf("packet:rrep:cipher:error '%v'", err)
				return
			}

			payload, err := aesgcm.Open(nil, rrep.Nonce, rrep.Cipher, headers)
			if err != nil {
				continue
			}

			session := SessionEntryFromRREP(random, &contact, *request, rrep, &sender, sessionSecret)
			network.sessionTable[rrep.SessionID] = &session

			network.logf("packet:rrep:session_established:%s:%d", contact, session.SessionID)
			network.SessionEstablished(contact, session.SessionID, sender, payload, true)
			break
		}
	} else {
		session := SessionEntryFromRREP(random, nil, *request, rrep, &sender, nil)
		network.sessionTable[rrep.SessionID] = &session

		network.forwardRouteReply(rrep, &session)
	}
}
