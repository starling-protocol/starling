package sync

import (
	"crypto/ed25519"
	"errors"
)

type PushPacket struct {
	senderPublicKey   NodePublicKey
	receiverPublicKey NodePublicKey
	delta             Deltas
	signature         Signature
}

func (model *Model) NewPushPacket(receiverPublicKey NodePublicKey, delta Deltas) *PushPacket {
	if delta == nil {
		delta = []Delta{}
	}

	header := pushPacketHeader(model.PublicKey, receiverPublicKey, delta)
	signature := ed25519.Sign(model.PrivateKey, header)

	return &PushPacket{
		senderPublicKey:   model.PublicKey,
		receiverPublicKey: receiverPublicKey,
		delta:             delta,
		signature:         signature,
	}
}

func pushPacketHeader(senderPublicKey NodePublicKey, receiverPublicKey NodePublicKey, delta Deltas) []byte {
	buf := []byte{byte(SYNC_PUSH)}
	buf = senderPublicKey.Encode(buf)
	buf = receiverPublicKey.Encode(buf)
	buf = delta.Encode(buf)
	return buf
}

func (packet *PushPacket) Encode() []byte {
	buf := pushPacketHeader(packet.senderPublicKey, packet.receiverPublicKey, packet.delta)
	buf = append(buf, packet.signature...)
	return buf
}

func DecodePushPacket(buf []byte) (*PushPacket, error) {
	if len(buf) < 69 {
		return nil, errors.New("error decoding push packet 'buffer too short'")
	}

	if buf[0] != byte(SYNC_PUSH) {
		return nil, errors.New("error decoding push packet 'invalid packet type'")
	}

	senderPublicKey := DecodeNodePublicKey(buf[1:33])
	receiverPublicKey := DecodeNodePublicKey(buf[33:65])

	delta, deltaCount, err := DecodeDeltas(buf[65:])
	if err != nil {
		return nil, err
	}

	signature := buf[65+deltaCount : 65+deltaCount+64]
	validSignature := ed25519.Verify(senderPublicKey.Key(), buf[0:65+deltaCount], signature)
	if !validSignature {
		return nil, errors.New("error decoding push packet 'invalid signature'")
	}

	return &PushPacket{
		senderPublicKey:   senderPublicKey,
		receiverPublicKey: receiverPublicKey,
		delta:             delta,
		signature:         signature,
	}, nil
}
