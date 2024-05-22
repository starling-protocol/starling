package transport_layer

import (
	"encoding/binary"
	"fmt"

	"github.com/starling-protocol/starling/device"
)

type ACKPacket struct {
	LatestSeqID   SequenceID
	MissingSeqIDs []SequenceID
}

func NewACKPacket(latestSeqID SequenceID, missingSeqIDs []SequenceID) *ACKPacket {
	return &ACKPacket{
		LatestSeqID:   latestSeqID,
		MissingSeqIDs: missingSeqIDs,
	}
}

func (d *ACKPacket) PacketType() PacketType {
	return ACK
}

func (d *ACKPacket) EncodePacket() []byte {
	buf := []byte{}

	buf = append(buf, byte(ACK))
	buf = d.LatestSeqID.Encode(buf)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(d.MissingSeqIDs)))
	for _, seq := range d.MissingSeqIDs {
		buf = binary.BigEndian.AppendUint32(buf, uint32(seq))
	}

	return buf
}

func DecodeACKPacket(buf []byte) (*ACKPacket, error) {
	if len(buf) < 9 {
		return nil, fmt.Errorf("buffer too small when decoding ACK packet: %d", len(buf))
	}

	if buf[0] != byte(ACK) {
		return nil, fmt.Errorf("wrong packet header when decoding ACP packet: %d", buf[0])
	}

	latestSeqID := DecodeSequenceID(buf[1:])
	count := int(binary.BigEndian.Uint32(buf[5:]))

	if len(buf) < 9+count*4 {
		return nil, fmt.Errorf("buffer too small when decoding '%d' missing seq ids in ACK packet: %d", count, len(buf))
	}

	missingAcks := make([]SequenceID, count)
	for i := 0; i < count; i++ {
		missingAcks[i] = DecodeSequenceID(buf[9+i*4:])
	}

	ackPacket := NewACKPacket(latestSeqID, missingAcks)

	return ackPacket, nil
}

func (transport *TransportLayer) handleACKPacket(sessionID device.SessionID, packet *ACKPacket) {
	transport.logf("packet:ack:handle:%d:%d", sessionID, packet.LatestSeqID)

	_, found := transport.networkLayer.GetSession(sessionID)
	if !found {
		transport.logf("packet:ack:handle:error:%d 'session was not found, ignoring packet'", sessionID)
		return
	}

	state := transport.SessionState(sessionID)

	resendPackets := state.ReceiveACK(transport, packet)

	for _, packet := range resendPackets {
		transport.networkLayer.SendData(sessionID, packet.EncodePacket())
	}
}
