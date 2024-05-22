package contact_bitmap_test

import (
	"math"
	"math/rand"
	"sort"
	"testing"

	"github.com/starling-protocol/starling/device"
	"github.com/starling-protocol/starling/network_layer/contact_bitmap"

	"github.com/stretchr/testify/assert"
)

func sampleContacts(t *testing.T, random *rand.Rand, count int) device.ContactsContainer {
	contactsContainer := device.NewMemoryContactsContainer()
	for i := 0; i < count/2; i++ {
		_, err := contactsContainer.NewGroup()
		assert.NoError(t, err)
	}

	for i := 0; i < int(math.Ceil(float64(count)/2.0)); i++ {
		var sharedSecret [32]byte
		_, err := random.Read(sharedSecret[:])
		assert.NoError(t, err)

		_, err = contactsContainer.NewLink(sharedSecret[:])
		assert.NoError(t, err)
	}

	return contactsContainer
}

func TestEncodeContactBitmap(t *testing.T) {
	random := rand.New(rand.NewSource(1))

	contactsContainer := sampleContacts(t, random, 3)
	contactIDs := contactsContainer.AllGroups()
	contactIDs = append(contactIDs, contactsContainer.AllLinks()...)

	result, err := contact_bitmap.EncodeContactBitmap(random, contactIDs, contactsContainer, 4)
	assert.NoError(t, err)
	assert.Equal(t, 3, result.ContactCount)
}

func TestContactBitmap(t *testing.T) {
	random := rand.New(rand.NewSource(2))

	contactsContainer := sampleContacts(t, random, 100)
	contactIDs := contactsContainer.AllGroups()
	contactIDs = append(contactIDs, contactsContainer.AllLinks()...)

	result, err := contact_bitmap.EncodeContactBitmap(random, contactIDs, contactsContainer, 5)
	assert.NoError(t, err)
	assert.Greater(t, result.ContactCount, 0)
	t.Logf("Encoded %d contacts", result.ContactCount)

	encodedContacts, err := contact_bitmap.DecodeContactBitmap(random, contactsContainer, result.Seed, result.Bitmap)
	assert.NoError(t, err)

	assert.Len(t, encodedContacts, result.ContactCount)
}

func FuzzContactBits(f *testing.F) {
	random := rand.New(rand.NewSource(1))

	for i := 0; i < 3; i++ {
		secret := [32]byte{}

		seed, err := contact_bitmap.RandomSeed(random)
		if err != nil {
			f.Fatal(err)
		}

		if _, err := random.Read(secret[:]); err != nil {
			f.Fatal(err)
		}

		f.Add(uint64(seed), secret[:])
	}

	f.Fuzz(func(t *testing.T, seed uint64, secret []byte) {
		if len(secret) != 3 {
			return
		}

		bits, err := contact_bitmap.ContactBits(contact_bitmap.Seed(seed), secret[:])
		assert.NoError(t, err)
		sort.Ints(bits)
		for i := 1; i < len(bits); i++ {
			assert.True(t, bits[i-1] != bits[i])
		}
	})
}
