package application_layer

import (
	"github.com/starling-protocol/starling/device"
)

type transportEvents struct {
	app *ApplicationLayer
}

// SessionEstablished implements transport_layer.TransportEvents.
func (t *transportEvents) SessionEstablished(session device.SessionID, contact device.ContactID, address device.DeviceAddress, payload []byte, isInitiator bool) {
	t.app.dev.SessionEstablished(session, contact, address)

	if len(payload) > 0 {
		t.app.handlePacket(session, contact, payload)
	}

	if isInitiator && t.app.options.EnableSync {
		packet, err := t.app.sync.PullPacket(contact)
		if err != nil {
			t.app.logf("reply_payload:error '%v'", err)
			return
		}

		data := packet.Encode()
		data = append([]byte{0x02}, data...)

		_, err = t.app.transportLayer.SendMessage(session, data)
		if err != nil {
			t.app.logf("sync:push_sync_updates:send:error '%v'", err)
			return
		}
	}
}

// SessionBroken implements transport_layer.TransportEvents.
func (t *transportEvents) SessionBroken(session device.SessionID) {
	t.app.dev.SessionBroken(session)

	if t.app.options.EnableSync {
		t.app.logf("sync:cleanup_session:%d", session)
		t.app.sync.SessionBroken(session)
	}
}

// ReplyPayload implements transport_layer.TransportEvents.
func (t *transportEvents) ReplyPayload(session device.SessionID, contact device.ContactID) []byte {
	if t.app.options.EnableSync {
		packet, err := t.app.sync.PullPacket(contact)
		if err != nil {
			t.app.logf("reply_payload:error '%v'", err)
			return nil
		}

		data := packet.Encode()
		data = append([]byte{0x02}, data...)
		return data
	}

	// Let the user specify what to piggyback
	packet := t.app.dev.ReplyPayload(session, contact)
	if len(packet) > 0 {
		packet = append([]byte{0x01}, packet...)
	}

	return packet
}

// MessageDelivered implements transport_layer.TransportEvents.
func (t *transportEvents) MessageDelivered(messageID device.MessageID) {
	if result, found := t.app.pendingSyncPushPackets[messageID]; found {
		t.app.logf("deliver_packet:sync:%d", messageID)
		err := t.app.sync.PushPacketDelivered(result.contact, result.session, result.packet)
		if err != nil {
			t.app.logf("deliver_packet:sync:err:%d '%v'", messageID, err)
		}
	} else {
		t.app.logf("deliver_packet:device:%d", messageID)
		t.app.dev.MessageDelivered(messageID)
	}
}
