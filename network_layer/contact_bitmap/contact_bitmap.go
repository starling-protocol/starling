package contact_bitmap

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"slices"
	"sort"

	"github.com/starling-protocol/starling/device"
)

const BITMAP_SIZE int = 2048 / 8

type Seed uint64
type ContactBitmap []byte

func (s Seed) Bytes() []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(s))
}

func RandomSeed(cryptoRandom io.Reader) (Seed, error) {
	buf := [8]byte{}

	if _, err := cryptoRandom.Read(buf[:]); err != nil {
		return 0, err
	}

	return Seed(binary.BigEndian.Uint64(buf[:])), nil
}

func getBit(bits []byte, index int) bool {
	return (bits[index/8] & (1 << (index % 8))) > 0
}

func setBit(bits []byte, index int, value bool) {
	if value {
		bits[index/8] |= 1 << (index % 8)
	} else {
		bits[index/8] &= ^(1 << (index % 8))
	}
}

func ContactBits(seed Seed, secret device.SharedSecret) ([]int, error) {
	if len(secret) != 32 {
		return nil, fmt.Errorf("wrong secret length, expected 32 got %d", len(secret))
	}
	bits := []int{}

	hasher := hmac.New(sha256.New, secret)

	if _, err := hasher.Write(seed.Bytes()); err != nil {
		return nil, err
	}

	hash := hasher.Sum(nil)

	for i := 0; i < 12; i++ {
		bitIndex := int(binary.LittleEndian.Uint16(hash[i*2:]) & 0x7FF)
		for slices.Contains(bits, bitIndex) {
			bitIndex = (bitIndex + 1) % 0x7FF
		}
		bits = append(bits, bitIndex)
	}

	return bits, nil
}

type ContactBitmapEncoding struct {
	Seed         Seed
	Bitmap       ContactBitmap
	ContactCount int
}

func EncodeContactBitmap(cryptoRandom io.Reader, prioritizedContactList []device.ContactID, contactsContainer device.ContactsContainer, attempts int) (*ContactBitmapEncoding, error) {

	bestBitmap := [BITMAP_SIZE]byte{}
	bestSeed := Seed(0)
	bestContactCount := -1

	for ; attempts > 0; attempts-- {
		seed, err := RandomSeed(cryptoRandom)
		if err != nil {
			return nil, err
		}

		contactCount := 0
		bitmap := [BITMAP_SIZE]byte{}
		if _, err := cryptoRandom.Read(bitmap[:]); err != nil {
			return nil, err
		}

		lockedBits := [BITMAP_SIZE]byte{}

	CONTACTS:
		for _, contactID := range prioritizedContactList {
			secret, err := contactsContainer.ContactSecret(contactID)
			if err != nil {
				return nil, err
			}

			contactBits, err := ContactBits(seed, secret)
			if err != nil {
				return nil, err
			}

			// Check for collisions
			for i, bit := range contactBits {
				if getBit(lockedBits[:], bit) && getBit(bitmap[:], bit) != (i%2 == 1) {
					continue CONTACTS
				}
			}

			// Since no collisions, set bits
			for i, bit := range contactBits {
				setBit(lockedBits[:], bit, true)
				setBit(bitmap[:], bit, i%2 == 1)
			}

			contactCount++
		}

		if contactCount > bestContactCount {
			bestContactCount = contactCount
			bestBitmap = bitmap
			bestSeed = seed
		}

		if contactCount == len(prioritizedContactList) {
			break
		}
	}

	return &ContactBitmapEncoding{
		Seed:         bestSeed,
		Bitmap:       bestBitmap[:],
		ContactCount: bestContactCount,
	}, nil
}

func DecodeContactBitmap(random *rand.Rand, contactsContainer device.ContactsContainer, seed Seed, bitmap ContactBitmap) ([]device.ContactID, error) {
	if len(bitmap) != BITMAP_SIZE {
		return nil, fmt.Errorf("expected length of data to be %d, got %d", BITMAP_SIZE, len(bitmap))
	}

	decodedContacts := []device.ContactID{}

	allContacts := contactsContainer.AllGroups()
	allContacts = append(allContacts, contactsContainer.AllLinks()...)

CONTACTS:
	for _, contactID := range allContacts {
		contactSecret, err := contactsContainer.ContactSecret(contactID)
		if err != nil {
			return nil, err
		}

		contactBits, err := ContactBits(seed, contactSecret)
		if err != nil {
			return []device.ContactID{}, err
		}

		for i, bit := range contactBits {
			if getBit(bitmap, bit) != (i%2 == 1) {
				continue CONTACTS
			}
		}
		decodedContacts = append(decodedContacts, contactID)
	}

	sort.Slice(decodedContacts, func(i, j int) bool {
		return decodedContacts[i] < decodedContacts[j]
	})

	return []device.ContactID(decodedContacts), nil
}
