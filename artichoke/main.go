package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/qbetti/go-artichoke/artichoke/pas"
)

func main() {
	key, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println(err)
	}

	crypto.SaveECDSA("key.priv", key)

	aesKey := make([]byte, 32)
	rand.Read(aesKey)
	fmt.Println(hex.EncodeToString(aesKey))

	action0 := "This is some random data to be signed"
	action1 := "Other data"

	seq := pas.NewPeerActionSequence()
	seq.Append([]byte(action0), key, "group0", aesKey)
	seq.Append([]byte(action1), key, "group0", aesKey)

	fmt.Println(seq)
	fmt.Println(seq.Verify())

	pa0 := seq.GetPeerAction(0)
	pa1 := seq.GetPeerAction(1)

	fmt.Println(pa0)
	fmt.Println(pa1)

	a0, _ := pa0.Decrypt(aesKey)
	a1, _ := pa1.Decrypt(aesKey)

	fmt.Println(string(a0))
	fmt.Println(string(a1))
}
