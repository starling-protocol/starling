package transport_layer

import (
	"cmp"
	"encoding/binary"
	"slices"
	"sync"
	"time"

	"github.com/starling-protocol/starling/device"
)

type SequenceID uint32

func (s SequenceID) Encode(buf []byte) []byte {
	return binary.BigEndian.AppendUint32(buf, uint32(s))
}

func DecodeSequenceID(buf []byte) SequenceID {
	return SequenceID(binary.BigEndian.Uint32(buf))
}

type ReceiverState struct {
	ackTimer         bool
	latestSeq        SequenceID
	missingSeqs      []SequenceID
	awaitingDelivery []*DATAPacket
}

type awaitingACK struct {
	message    outboxMessage
	sequenceID SequenceID
	timestamp  time.Time
}

func newAwaitingACK(sequenceID SequenceID, message outboxMessage, timestamp time.Time) awaitingACK {
	return awaitingACK{
		sequenceID: sequenceID,
		message:    message,
		timestamp:  timestamp,
	}
}

type SenderState struct {
	timeoutTimer   bool
	awaitingACKs   []awaitingACK
	nextSequenceID SequenceID
}

type SessionState struct {
	sendLock    sync.Mutex
	receiveLock sync.Mutex
	sessionID   device.SessionID
	sender      *SenderState
	receiver    *ReceiverState
}

func NewSessionState(sessionID device.SessionID) *SessionState {
	return &SessionState{
		sessionID: sessionID,
		sender: &SenderState{
			timeoutTimer:   false,
			awaitingACKs:   []awaitingACK{},
			nextSequenceID: 1,
		},
		receiver: &ReceiverState{
			ackTimer:    false,
			latestSeq:   0,
			missingSeqs: []SequenceID{},
		},
	}
}

// DeliverMessage registers a message as awaiting an ack,
// it returns the sequence ID for the new packet to be delivered.
func (state *SessionState) DeliverMessage(transport *TransportLayer, message outboxMessage) SequenceID {
	state.sendLock.Lock()
	seqID := state.sender.nextSequenceID
	state.sender.nextSequenceID++
	state.sender.awaitingACKs = append(state.sender.awaitingACKs, newAwaitingACK(seqID, message, transport.dev.Now()))
	state.sendLock.Unlock()

	state.startTimeoutTimer(transport)

	return seqID
}

func (state *SessionState) ReceiveACK(transport *TransportLayer, packet *ACKPacket) []*DATAPacket {
	state.sendLock.Lock()
	defer state.sendLock.Unlock()

	resendPackets := []*DATAPacket{}
	newAwaitingACKs := []awaitingACK{}

	for _, awaiting := range state.sender.awaitingACKs {
		seqID := awaiting.sequenceID

		// Look at all relevant msgs in awaitingACK
		if seqID <= packet.LatestSeqID {
			if slices.Contains(packet.MissingSeqIDs, seqID) {
				// Resend the msg
				dataPacket := NewDATAPacket(seqID, awaiting.message.body)
				resendPackets = append(resendPackets, dataPacket)
				newAwaitingACKs = append(newAwaitingACKs, awaiting)
			} else {
				// Message has been delivered
				transport.events.MessageDelivered(awaiting.message.messageID)
			}
		}
	}

	transport.logf("packet:ack:handle:done:%d:%d '%d message(s) delivered'", len(resendPackets), len(state.sender.awaitingACKs), len(state.sender.awaitingACKs)-len(resendPackets))
	state.sender.awaitingACKs = newAwaitingACKs

	return resendPackets
}

// Updates the local state with the incoming packet.
// Returns a list of packets (in ascending sorted order by their sequence ID) that can now be delivered.
func (state *SessionState) ReceiveDATA(transport *TransportLayer, packet *DATAPacket) []*DATAPacket {
	state.startAckTimer(transport)

	state.receiveLock.Lock()
	defer state.receiveLock.Unlock()

	packetsToDeliver := []*DATAPacket{}

	if state.receiver.latestSeq < packet.SeqID {
		// Add potential missing sequenceIDs
		for seq := state.receiver.latestSeq + 1; seq < packet.SeqID; seq++ {
			state.receiver.missingSeqs = append(state.receiver.missingSeqs, seq)
		}
		state.receiver.latestSeq = packet.SeqID
	}

	if len(state.receiver.missingSeqs) != 0 {
		if state.receiver.missingSeqs[0] == packet.SeqID {
			// This packet was the earliest missing packet

			deliverUntil := state.receiver.latestSeq + 1
			if len(state.receiver.missingSeqs) >= 2 {
				// Deliver until next missing packet
				deliverUntil = state.receiver.missingSeqs[1]
			}

			newAwaitingDelivery := []*DATAPacket{}
			for _, p := range state.receiver.awaitingDelivery {
				if p.SeqID < deliverUntil {
					// Packet should be delivered
					packetsToDeliver = append(packetsToDeliver, p)
				} else {
					// Packet should not be delivered, and thus is readded to awaitingDelivery
					newAwaitingDelivery = append(newAwaitingDelivery, p)
				}
			}
			state.receiver.awaitingDelivery = newAwaitingDelivery

			packetsToDeliver = append(packetsToDeliver, packet)

		} else if state.receiver.missingSeqs[0] < packet.SeqID {
			// There is a packet we have not received yet before this packet. Add this packet to awaitingDelivery
			state.receiver.awaitingDelivery = append(state.receiver.awaitingDelivery, packet)
		}
	} else {
		// No missing packets. Thus deliver received packet.
		packetsToDeliver = append(packetsToDeliver, packet)
	}

	//Check if incoming sequenceID is in missingSeqs and remove it
	for i, missing := range state.receiver.missingSeqs {
		if packet.SeqID == missing {
			state.receiver.missingSeqs = append(state.receiver.missingSeqs[:i], state.receiver.missingSeqs[i+1:]...)
			break
		}
	}

	slices.SortFunc(packetsToDeliver, func(a *DATAPacket, b *DATAPacket) int {
		return cmp.Compare(int(a.SeqID), int(b.SeqID))
	})
	return packetsToDeliver
}

func (state *SessionState) startAckTimer(transport *TransportLayer) {
	state.receiveLock.Lock()

	if state.receiver.ackTimer {
		state.receiveLock.Unlock()
		return
	}

	transport.logf("session:timer:ack:starting_timer:%d 'Starting ack timer'", state.sessionID)
	state.receiver.ackTimer = true
	state.receiveLock.Unlock()

	transport.dev.Delay(func() {
		state.receiveLock.Lock()
		ackPacket := NewACKPacket(state.receiver.latestSeq, state.receiver.missingSeqs)
		sessionID := state.sessionID
		state.receiver.ackTimer = false
		state.receiveLock.Unlock()

		_, found := transport.networkLayer.GetSession(sessionID)
		if !found {
			transport.logf("session:timer:ack:send:error:%d 'Session not found'", sessionID)
			return
		}

		transport.logf("session:timer:ack:send:%d 'Sending ack reply'", sessionID)
		transport.networkLayer.SendData(sessionID, ackPacket.EncodePacket())
	}, transport.options.ACKDelay)
}

func (state *SessionState) startTimeoutTimer(transport *TransportLayer) {
	state.sendLock.Lock()

	if state.sender.timeoutTimer {
		state.sendLock.Unlock()
		return
	}

	if len(state.sender.awaitingACKs) == 0 {
		state.sendLock.Unlock()
		return
	}

	timeoutACK := state.sender.awaitingACKs[0]

	transport.logf("session:timer:timeout:starting:%d 'starting session timeout timer'", state.sessionID)
	state.sender.timeoutTimer = true
	state.sendLock.Unlock()

	timeSinceCreated := transport.dev.Now().Sub(timeoutACK.timestamp)
	delay := transport.options.ACKTimeout - timeSinceCreated

	transport.dev.Delay(func() {
		state.sendLock.Lock()

		seqIDAcked := true
		for _, awaiting := range state.sender.awaitingACKs {
			if awaiting.sequenceID == timeoutACK.sequenceID {
				seqIDAcked = false
				break
			}
		}

		if seqIDAcked {
			state.sender.timeoutTimer = false
			state.sendLock.Unlock()
			state.startTimeoutTimer(transport)
			return
		}

		transport.logf("session:timer:timeout:timed_out:%d 'session timer timed out, breaking connection'", state.sessionID)
		state.sendLock.Unlock()

		transport.TimeoutSession(state.sessionID)
	}, delay)
}

func (transport *TransportLayer) TimeoutSession(sessionID device.SessionID) {
	transport.logf("session:timeout:cleanup:%d 'removing timed out session'", sessionID)

	state, found := transport.sessionStates[sessionID]
	if !found {
		transport.log("session:timeout:cleanup:error 'session not found, ignoring timeout session'")
		return
	}

	state.receiveLock.Lock()
	state.sendLock.Lock()

	transport.networkLayer.SessionBroken(sessionID, nil)
	delete(transport.sessionStates, sessionID)

	state.sendLock.Unlock()
	state.receiveLock.Unlock()
}
