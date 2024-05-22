package mobile

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/starling-protocol/starling/device"
)

type LinkSession interface {
	GetShare() []byte
}

type ContactsContainer interface {
	ContactSecret(contact string) ([]byte, error)
	DeleteContact(contact string)

	AllGroups() string
	AllLinks() string

	JoinGroup(groupSecret []byte) (string, error)

	NewLink(linkSecret []byte) (string, error)
}

type contactsContainerWrapper struct {
	cont ContactsContainer
}

func newContactsContainerWrapper(contactsContainer ContactsContainer) *contactsContainerWrapper {
	return &contactsContainerWrapper{
		cont: contactsContainer,
	}
}

// AllGroups implements device.ContactsContainer.
func (c *contactsContainerWrapper) AllGroups() []device.ContactID {
	groupBlock := c.cont.AllGroups()

	if len(groupBlock) == 0 {
		return []device.ContactID{}
	}

	groupStrings := strings.Split(groupBlock, ";")

	groups := []device.ContactID{}
	for _, group := range groupStrings {
		groups = append(groups, device.ContactID(group))
	}

	return groups

	// groupsPtr := (*device.ContactID)(unsafe.Pointer(&groups[0]))
	// return unsafe.Slice(groupsPtr, len(groups))
}

// AllLinks implements device.ContactsContainer.
func (c *contactsContainerWrapper) AllLinks() []device.ContactID {
	linkBlock := c.cont.AllLinks()

	if len(linkBlock) == 0 {
		return []device.ContactID{}
	}

	linkStrings := strings.Split(linkBlock, ";")

	links := []device.ContactID{}
	for _, link := range linkStrings {
		links = append(links, device.ContactID(link))
	}

	return links

	// linksPtr := (*device.ContactID)(unsafe.Pointer(&links[0]))
	// return unsafe.Slice(linksPtr, len(links))
}

// ContactSecret implements device.ContactsContainer.
func (c *contactsContainerWrapper) ContactSecret(contact device.ContactID) (device.SharedSecret, error) {
	secret, err := c.cont.ContactSecret(string(contact))
	return device.SharedSecret(secret), err
}

// DeleteContact implements device.ContactsContainer.
func (c *contactsContainerWrapper) DeleteContact(contact device.ContactID) {
	c.cont.DeleteContact(string(contact))
}

// JoinGroup implements device.ContactsContainer.
func (c *contactsContainerWrapper) JoinGroup(groupSecret device.SharedSecret) (device.ContactID, error) {
	contact, err := c.cont.JoinGroup([]byte(groupSecret))
	return device.ContactID(contact), err
}

// NewGroup implements device.ContactsContainer.
func (c *contactsContainerWrapper) NewGroup() (device.ContactID, error) {
	var buf [32]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		return "", fmt.Errorf("failed to generate random secret: '%w'", err)
	}

	return c.JoinGroup(buf[:])
}

// NewLink implements device.ContactsContainer.
func (c *contactsContainerWrapper) NewLink(linkSecret device.SharedSecret) (device.ContactID, error) {
	contact, err := c.cont.NewLink(linkSecret)
	return device.ContactID(contact), err
}
