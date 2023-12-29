package main

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Vaudenay SAS protocol (https://www.iacr.org/archive/crypto2005/36210303/36210303.pdf)
// Improved by MA-3 protocol (https://eprint.iacr.org/2005/424.pdf)
// Based on an Ideal Commitment Model.
// The exchanged messages could be the hashes of public keys.

func main() {
	alice := newPerson("AlicePublicKey")
	bob := newPerson("BobPublicKey")

	// Alice sends commitment and message to Bob
	alice.commitTo(bob)

	// Bob sends message and nonce to Alice
	bob.sendTo(alice)

	// Alice reveals the nonce to Bob
	alice.commitment.decommit()

	// Both parties calculate the pin
	fmt.Println(alice.initiatorCheck())
	fmt.Println(bob.secondaryCheck())
}

type person struct {
	r          []byte
	msg        []byte
	commitment *commitment
	other      *person
}

func newPerson(msg string) *person {
	r := make([]byte, aes.BlockSize)
	_, err := rand.Read(r)
	if err != nil {
		panic(err.Error())
	}

	return &person{
		r:     r,
		msg:   []byte(msg),
		other: &person{},
	}
}

// commitTo sends the message and the newly created commitment to the other person
func (p *person) commitTo(the *person) {
	p.commitment = newCommitment(p.r)
	the.other.commitment = p.commitment
	the.other.msg = p.msg
}

// sendTo sends the message and the nonce to the other person
func (p *person) sendTo(the *person) {
	the.other.msg = p.msg
	the.other.r = p.r
}

// initiatorCheck calculates the pin for the initiator of the protocol
func (p *person) initiatorCheck() string {
	c, err := aes.NewCipher(p.r)
	if err != nil {
		panic(err.Error())
	}

	aKey := make([]byte, c.BlockSize())
	c.Encrypt(aKey, p.other.r)

	aCheck := hmac.New(sha256.New, aKey)
	aCheck.Write(p.msg)
	aCheck.Write(p.other.msg)
	return retrievePin(aCheck.Sum(nil), 8)
}

// secondaryCheck calculates the pin for the secondary of the protocol
func (p *person) secondaryCheck() string {
	aRand, err := p.other.commitment.open()
	if err != nil {
		panic(err.Error())
	}

	c, err := aes.NewCipher(aRand)
	if err != nil {
		panic(err.Error())
	}

	bKey := make([]byte, c.BlockSize())
	c.Encrypt(bKey, p.r)

	bCheck := hmac.New(sha256.New, bKey)
	bCheck.Write(p.other.msg)
	bCheck.Write(p.msg)
	return retrievePin(bCheck.Sum(nil), 8)
}

// retrievePin returns a pin of the specified length based on the given (random) bytes
func retrievePin(r []byte, maxLength int) string {
	// Create a string containing only the digits 0-9
	digitString := ""
	for _, b := range r {
		digitString += fmt.Sprintf("%d", int(b)%10)
		if len(digitString) == maxLength {
			break
		}
	}

	return digitString
}

// commitment models an ideal commitment scheme
type commitment struct {
	message     []byte
	isProtected bool
}

// open returns the message if the commitment is not protected
func (c *commitment) open() ([]byte, error) {
	if c.isProtected {
		return nil, errors.New("commitment is protected")
	}
	return c.message, nil
}

// decommit makes the commitment unprotected
func (c *commitment) decommit() {
	c.isProtected = false
}

// newCommitment creates a new protected commitment
func newCommitment(c []byte) *commitment {
	return &commitment{
		message:     c,
		isProtected: true,
	}
}
