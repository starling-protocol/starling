package transport_layer

import (
	"fmt"

	"github.com/starling-protocol/starling/device"
)

type DATAPacket struct {
	SeqID SequenceID
	Data  []byte
}

func NewDATAPacket(seqID SequenceID, data []byte) *DATAPacket {
	return &DATAPacket{
		SeqID: seqID,
		Data:  data,
	}
}

func (d *DATAPacket) PacketType() PacketType {
	return DATA
}

func (d *DATAPacket) EncodePacket() []byte {
	buf := []byte{}

	buf = append(buf, byte(DATA))
	buf = d.SeqID.Encode(buf)
	buf = append(buf, d.Data...)

	return buf
}

func DecodeDataPacket(buf []byte) (*DATAPacket, error) {
	if len(buf) < 5 {
		return nil, fmt.Errorf("buffer too small when decoding DATA packet: %d", len(buf))
	}

	if buf[0] != byte(DATA) {
		return nil, fmt.Errorf("wrong packet header when decoding ACP packet: %d", buf[0])
	}

	seqID := DecodeSequenceID(buf[1:])
	data := buf[5:]

	dataPacket := NewDATAPacket(seqID, data)

	return dataPacket, nil
}

func (transport *TransportLayer) handleDataPacket(sessionID device.SessionID, packet *DATAPacket) []TransportMessage {
	transport.logf("packet:data:handle:%d:%d", sessionID, packet.SeqID)

	session, found := transport.networkLayer.GetSession(sessionID)
	if !found {
		transport.logf("packet:data:handle:error:%d 'session was not found, ignoring packet'", sessionID)
		return nil
	}

	state := transport.SessionState(sessionID)

	packets := state.ReceiveDATA(transport, packet)

	messagesToDeliver := []TransportMessage{}
	for _, p := range packets {
		messagesToDeliver = append(messagesToDeliver, TransportMessage{
			Contact: *session.Contact,
			Session: sessionID,
			Data:    p.Data,
		})
	}

	return messagesToDeliver
}
