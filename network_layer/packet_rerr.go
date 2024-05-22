package network_layer

import (
	"fmt"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/utils"
)

type RERRPacket struct {
	SessionID device.SessionID
}

func NewRERR(sessionID device.SessionID) *RERRPacket {
	return &RERRPacket{
		SessionID: sessionID,
	}
}

func (p *RERRPacket) PacketType() PacketType {
	return RERR
}

func (p *RERRPacket) EncodePacket() []byte {
	buf := []byte{}
	buf = append(buf, byte(RERR))

	buf = EncodeSessionID(p.SessionID, buf)
	return buf
}

func DecodeRERR(buf []byte) (*RERRPacket, error) {
	if len(buf) < 9 {
		return nil, fmt.Errorf("buffer too small when decoding RERR: %d", len(buf))
	}

	if buf[0] != byte(RERR) {
		return nil, fmt.Errorf("wrong packet header when decoding RERR packet: %d", buf[0])
	}

	return NewRERR(DecodeSessionID(buf[1:])), nil
}

func (network *NetworkLayer) handleRouteErrorPacket(rerr RERRPacket, sender device.DeviceAddress) {
	sessID := rerr.SessionID
	entry, found := network.sessionTable[sessID]
	if !found {
		network.logf("packet:rerr:receive:session_not_found:error:%d", sessID)
		return
	}

	network.logf("packet:rerr:receive:%s", sender)

	if entry.SourceNeighbour == nil || entry.TargetNeighbour == nil {
		// We are one of the contacts
		network.logf("packet:rerr:session_broken:%s", sender)
		network.SessionBroken(sessID, &sender)
	} else {
		if sender == *entry.SourceNeighbour {
			network.sendRouteError(*entry.TargetNeighbour, sessID)
		} else if sender == *entry.TargetNeighbour {
			network.sendRouteError(*entry.SourceNeighbour, sessID)
		}

		delete(network.sessionTable, sessID)
	}
}

func (network *NetworkLayer) sendRouteError(targetAddr device.DeviceAddress, sessID device.SessionID) {
	packet := NewRERR(sessID)
	network.logf("packet:rerr:send:%s", targetAddr)
	network.packetLayer.SendBytes(targetAddr, packet.EncodePacket())
}

func (network *NetworkLayer) handleDisconnect(failedNode device.DeviceAddress) {
	// Check if we have session related to the failed node
	for _, sessID := range utils.ShuffleMapKeys(network.dev.Rand(), network.sessionTable) {
		entry := network.sessionTable[sessID]

		if (entry.SourceNeighbour == nil && entry.TargetNeighbour != nil && *entry.TargetNeighbour == failedNode) ||
			(entry.TargetNeighbour == nil && entry.SourceNeighbour != nil && *entry.SourceNeighbour == failedNode) {
			network.logf("disconnect:session_broken:%s", failedNode)
			network.SessionBroken(sessID, &failedNode)
		} else if entry.SourceNeighbour != nil && entry.TargetNeighbour != nil {
			source := *entry.SourceNeighbour
			target := *entry.TargetNeighbour

			// Make sure to send error packet the correct direction if applicable
			if source == failedNode {
				network.sendRouteError(target, entry.SessionID)
				delete(network.sessionTable, sessID)
			} else if target == failedNode {
				network.sendRouteError(source, entry.SessionID)
				delete(network.sessionTable, sessID)
			}
		}
	}
}
