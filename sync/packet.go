package sync

import (
	"errors"

	"github.com/starling-protocol/starling/device"
)

type SyncPacketType byte

const (
	SYNC_PULL SyncPacketType = iota
	SYNC_PUSH
)

func (sync *Sync) ReceiveSyncPacket(contact device.ContactID, session device.SessionID, packet []byte) error {
	packetType := SyncPacketType(packet[0])
	switch packetType {
	case SYNC_PULL:
		pullPacket, err := DecodePullPacket(packet)
		if err != nil {
			return err
		}

		return sync.HandlePullPacket(session, contact, pullPacket.senderPublicKey, pullPacket.digest)
	case SYNC_PUSH:
		pushPacket, err := DecodePushPacket(packet)
		if err != nil {
			return err
		}

		return sync.MergePushPacket(session, contact, pushPacket)
	default:
		return errors.New("invalid packet type")
	}
}

func (sync *Sync) PushPacketDelivered(contact device.ContactID, session device.SessionID, packet *PushPacket) error {
	sync.logf("packet:push:delivered:%d", session)
	recipient := packet.receiverPublicKey

	digestsUpdated := 0
	maxVersion := Version(0)
	for _, delta := range packet.delta {
		digestUpdate := sync.state[contact].UpdateDigest(recipient, delta.PublicKey, delta.Version)
		if digestUpdate {
			digestsUpdated += 1
		}
		maxVersion = max(maxVersion, sync.state[contact].Digests[recipient].Nodes[delta.PublicKey])
	}

	sync.state[contact].Digests[recipient].MaxVersion =
		max(sync.state[contact].Digests[recipient].MaxVersion, maxVersion)

	sync.logf("packet:push:delivered:digests_updated:%d", digestsUpdated)
	if digestsUpdated > 0 {
		if err := sync.notifyStateChanges(contact); err != nil {
			return err
		}
	}

	return nil
}
