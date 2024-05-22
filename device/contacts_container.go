package device

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

type ContactsContainer interface {
	ContactSecret(contact ContactID) (SharedSecret, error)
	DeleteContact(contact ContactID)

	AllGroups() []ContactID
	AllLinks() []ContactID

	NewGroup() (ContactID, error)
	JoinGroup(groupSecret SharedSecret) (ContactID, error)

	NewLink(linkSecret SharedSecret) (ContactID, error)
}

// toContactID is used to derive the device.ContactID from a device.SharedSecret
func (secret SharedSecret) toContactID() (ContactID, error) {
	aesCipher, err := aes.NewCipher(secret)
	if err != nil {
		return ContactID(""), err
	}

	zeros := make([]byte, aes.BlockSize)
	encrypted := make([]byte, aes.BlockSize)

	aesCipher.Encrypt(encrypted, zeros)

	hash := sha256.Sum256(encrypted)
	return ContactID(base64.StdEncoding.EncodeToString(hash[:])), nil
}

type MemoryContactsContainer struct {
	links  map[ContactID]SharedSecret
	groups map[ContactID]SharedSecret
}

func NewMemoryContactsContainer() *MemoryContactsContainer {
	return &MemoryContactsContainer{
		links:  map[ContactID]SharedSecret{},
		groups: map[ContactID]SharedSecret{},
	}
}

func (c *MemoryContactsContainer) ContactSecret(contact ContactID) (SharedSecret, error) {
	if secret, found := c.links[contact]; found {
		return secret, nil
	}

	if secret, found := c.groups[contact]; found {
		return secret, nil
	}

	return nil, errors.New("contact not found")
}

func (c *MemoryContactsContainer) DeleteContact(contact ContactID) {
	delete(c.links, contact)
	delete(c.groups, contact)
}

func (c *MemoryContactsContainer) AllGroups() []ContactID {
	groups := []ContactID{}
	for group := range c.groups {
		groups = append(groups, group)
	}
	return groups
}

func (c *MemoryContactsContainer) AllLinks() []ContactID {
	links := []ContactID{}
	for link := range c.links {
		links = append(links, link)
	}
	return links
}

func (c *MemoryContactsContainer) NewGroup() (ContactID, error) {
	var buf [32]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		return "", fmt.Errorf("failed to generate random secret: '%w'", err)
	}

	groupSecret := SharedSecret(buf[:])
	return c.JoinGroup(groupSecret)
}

func (c *MemoryContactsContainer) JoinGroup(groupSecret SharedSecret) (ContactID, error) {
	contactID, err := groupSecret.toContactID()
	if err != nil {
		return "", fmt.Errorf("failed to generate contact id: '%w'", err)
	}

	_, found := c.groups[contactID]
	if found {
		return "", fmt.Errorf("group already joined '%v'", contactID)
	}

	c.groups[contactID] = groupSecret
	return contactID, nil
}

func (c *MemoryContactsContainer) NewLink(linkSecret SharedSecret) (ContactID, error) {
	contactID, err := linkSecret.toContactID()
	if err != nil {
		return "", fmt.Errorf("failed to generate contact id: '%w'", err)
	}

	c.links[contactID] = linkSecret
	return contactID, nil
}

func (c *MemoryContactsContainer) DebugLink(sharedSecret SharedSecret) ContactID {
	contactID, err := sharedSecret.toContactID()
	if err != nil {
		panic(fmt.Sprintf("failed to debug link: %v", err))
	}

	c.links[contactID] = sharedSecret
	return contactID
}
