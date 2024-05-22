package mobile

import (
	"github.com/starling-protocol/starling"
	"github.com/starling-protocol/starling/contacts"
	"github.com/starling-protocol/starling/device"
)

type ProtocolOptions struct {
	EnableSync bool
}

func (p *ProtocolOptions) bindings() *device.ProtocolOptions {
	if p == nil {
		return nil
	}

	return device.DefaultSyncProtocolOptions()
}

type Protocol struct {
	proto *starling.Protocol
}

func NewProtocol(device Device, contactsContainer ContactsContainer, options *ProtocolOptions) *Protocol {
	return &Protocol{
		proto: starling.NewProtocol(newDeviceWrapper(device, contactsContainer), options.bindings()),
	}
}

func (p *Protocol) DeinitCleanup() {
	p.proto = nil
}

func (p *Protocol) LoadPersistedState() {
	p.proto.LoadPersistedState()
}

func (p *Protocol) OnConnection(address string) {
	p.proto.OnConnection(device.DeviceAddress(address))
}

func (p *Protocol) OnDisconnection(address string) {
	p.proto.OnDisconnection(device.DeviceAddress(address))
}

func (p *Protocol) SendMessage(session int64, message []byte) (int64, error) {
	msgID, err := p.proto.SendMessage(device.SessionID(session), message)
	return int64(msgID), err
}

func (p *Protocol) NewGroup() (string, error) {
	contact, err := p.proto.NewGroup()
	return string(contact), err
}

func (p *Protocol) JoinGroup(secret []byte) (string, error) {
	contact, err := p.proto.JoinGroup(secret)
	return string(contact), err
}

func (p *Protocol) ReceivePacket(address string, packet []byte) {
	p.proto.ReceivePacket(device.DeviceAddress(address), packet)
}

func (p *Protocol) BroadcastRouteRequest() {
	p.proto.BroadcastRouteRequest()
}

func (p *Protocol) SyncAddMessage(contact string, message []byte, attachedContact string) error {
	var attachment *device.ContactID = nil
	if attachedContact != "" {
		contact := device.ContactID(attachedContact)
		attachment = &contact
	}

	return p.proto.SyncAddMessage(device.ContactID(contact), message, attachment)
}

func (p *Protocol) SyncLoadState(contact string, state []byte) error {
	return p.proto.SyncLoadState(device.ContactID(contact), state)
}

func (p *Protocol) LinkingStart() (*LinkingSession, error) {
	ls, err := p.proto.LinkingStart()
	if err != nil {
		return nil, err
	}

	return &LinkingSession{ls: ls}, nil
}

func (p *Protocol) LinkingCreate(session *LinkingSession, remoteKey []byte) (string, error) {
	contact, err := p.proto.LinkingCreate(session.ls, remoteKey)
	return string(contact), err
}

func (p *Protocol) DeleteContact(contact string) {
	p.proto.DeleteContact(device.ContactID(contact))
}

type LinkingSession struct {
	ls *contacts.LinkingSession
}

func (l *LinkingSession) GetShare() []byte {
	return l.ls.GetShare()
}
