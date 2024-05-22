package network_layer

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/starling-protocol/starling/device"
)

type SESSPacket struct {
	SessionID device.SessionID
	Nonce     []byte
	Cipher    []byte
}

type SessionMessage struct {
	sessionID device.SessionID
	data      []byte
}

func (d *SessionMessage) SessionID() device.SessionID {
	return d.sessionID
}

func (d *SessionMessage) Data() []byte {
	return d.data
}

func newSessionMessage(sessionID device.SessionID, data []byte) *SessionMessage {
	return &SessionMessage{
		sessionID: sessionID,
		data:      data,
	}
}

func (network *NetworkLayer) NewSESSPacket(sessionID device.SessionID, data []byte) (*SESSPacket, error) {
	cryptoRand := network.dev.CryptoRand()

	nonce := make([]byte, 12)
	if _, err := cryptoRand.Read(nonce); err != nil {
		return nil, err
	}

	session, found := network.sessionTable[sessionID]
	if !found {
		return nil, errors.New("session not found")
	}

	if session.Contact == nil {
		return nil, errors.New("intermediary session id")
	}

	if session.SessionSecret == nil {
		return nil, errors.New("invalid session, no session secret")
	}

	aesCipher, err := aes.NewCipher(session.SessionSecret)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	headers := []byte(fmt.Sprintf("%d", sessionID))
	cipher := aesgcm.Seal(nil, nonce, data, headers)

	return &SESSPacket{
		SessionID: sessionID,
		Nonce:     nonce,
		Cipher:    cipher,
	}, nil
}

func (network *NetworkLayer) SendData(session device.SessionID, data []byte) error {
	sessionEntry, found := network.sessionTable[session]
	if !found {
		err := errors.New("session not found in session table")
		network.logf("send:sess:error '%v'", err)
		return err
	}

	neighbour := sessionEntry.TargetNeighbour
	if neighbour == nil {
		neighbour = sessionEntry.SourceNeighbour
	}

	packet, err := network.NewSESSPacket(sessionEntry.SessionID, data)
	if err != nil {
		network.logf("send:sess:error '%v'", err)
		return err
	}

	network.logf("send:sess:session:%d:%v:%s", sessionEntry.SessionID, *neighbour, base64.StdEncoding.EncodeToString(data))
	network.packetLayer.SendBytes(*neighbour, packet.EncodePacket())

	return nil
}

// func (network *NetworkLayer) SendDataToContact(contact device.ContactID, data []byte) error {
// 	session := network.GetSessionFromContact(contact)
// 	if session == nil {
// 		err := errors.New("session for contact not found")
// 		network.logf("send:sess:error '%v'", err)
// 		return err
// 	}

// 	network.logf("send:sess:contact:%s:%s", contact, base64.StdEncoding.EncodeToString(data))
// 	return network.SendData(session, data)
// }

func (network *NetworkLayer) handleSESSPacket(packet *SESSPacket, sender device.DeviceAddress) *SessionMessage {

	session, found := network.sessionTable[packet.SessionID]
	if !found {
		network.log("packet:sess:session:not_found")
		return nil
	}

	network.logf("packet:sess:receive_packet:%s", sender)

	if session.SourceNeighbour == nil || session.TargetNeighbour == nil {
		decrypted, err := network.decryptSESSPacket(packet, sender, session)
		if err != nil {
			network.logf("packet:sess:error_decrypting:%s '%s'", sender, err)
			return nil
		}

		network.logf("packet:sess:decrypted:%s:%s", sender, base64.StdEncoding.EncodeToString(decrypted.Data()))

		return decrypted
	}

	fromAddr := *session.SourceNeighbour
	toAddr := *session.TargetNeighbour
	if fromAddr != sender {
		fromAddr, toAddr = toAddr, fromAddr
		if fromAddr != sender {
			network.log("packet:sess:session:wrong_sender")
			return nil
		}
	}

	// Forward packet
	network.logf("packet:sess:forward:%s", toAddr)
	network.packetLayer.SendBytes(toAddr, packet.EncodePacket())
	return nil
}

func (network *NetworkLayer) decryptSESSPacket(packet *SESSPacket, sender device.DeviceAddress, session *SessionTableEntry) (*SessionMessage, error) {
	// var contact *device.ContactID = nil

	// LOOP_SESSIONS:
	// 	for con, sessionEntries := range network.contactSessions {
	// 		for _, sess := range sessionEntries {
	// 			if sess.SessionID == session.SessionID {
	// 				contact = &con
	// 				break LOOP_SESSIONS
	// 			}
	// 		}
	// 	}

	if session.Contact == nil {
		network.log("packet:sess:decrypt:contact_not_found")
		return nil, errors.New("contact not found")
	}
	contact := *session.Contact

	aesCipher, err := aes.NewCipher(session.SessionSecret)
	if err != nil {
		network.logf("packet:sess:cipher:error '%v'", err)
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		network.logf("packet:sess:cipher:error '%v'", err)
		return nil, err
	}

	headers := []byte(fmt.Sprintf("%d", packet.SessionID))
	data, err := aesgcm.Open(nil, packet.Nonce, packet.Cipher, headers)
	if err != nil {
		network.logf("packet:sess:cipher:error '%v'", err)
		return nil, err
	}

	network.logf("packet:sess:receive:%s 'data receive %d bytes'", contact, len(data))
	return newSessionMessage(packet.SessionID, data), nil
}

func (packet *SESSPacket) EncodePacket() []byte {
	buf := []byte{}
	buf = append(buf, byte(SESS))                                           // 1 bytes
	buf = EncodeSessionID(packet.SessionID, buf)                            // 8 bytes
	buf = append(buf, packet.Nonce...)                                      // 12 bytes
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(packet.Cipher)-16)) // 4 bytes
	buf = append(buf, packet.Cipher...)                                     // size + 16 bytes
	return buf
}

func (*SESSPacket) PacketType() PacketType {
	return SESS
}

func DecodeSESS(buf []byte) (*SESSPacket, error) {
	if len(buf) < 41 {
		return nil, fmt.Errorf("buffer too small when decoding SESS: %d", len(buf))
	}

	if buf[0] != byte(SESS) {
		return nil, fmt.Errorf("wrong packet header when decoding SESS packet: %d", buf[0])
	}

	sessID := DecodeSessionID(buf[1:])
	nonce := buf[9:21]
	size := binary.BigEndian.Uint32(buf[21:25])

	if len(buf) < 41+int(size) {
		return nil, fmt.Errorf("buffer too small when decoding SESS cipher: buffer: %d size: %d", len(buf), size)
	}
	cipher := buf[25 : 25+size+16]

	return &SESSPacket{
		SessionID: sessID,
		Nonce:     nonce,
		Cipher:    cipher,
	}, nil
}
