package artichoke

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/qbetti/go-artichoke/artichoke/generator"
	"github.com/qbetti/go-artichoke/artichoke/pas"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
	"time"
)

func TestKey(t *testing.T) {
	peerKey, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println(err)
	}

	crypto.SaveECDSA("peerkey.priv", peerKey)

	groupKey := make([]byte, 32)
	rand.Read(groupKey)
	//fmt.Println(hex.EncodeToString(groupKey))

	//action0 := "This is some random data to be signed"
	//action1 := "Other data"

	actions := generator.GenerateRandomActions(1000, 100)
	seq := pas.NewPeerActionSequence()

	for i := 0; i < len(actions); i++ {
		seq.Append(actions[i], peerKey, "myGroup", groupKey)
	}

	//seq.Append([]byte(action0), peerKey, "group0", groupKey)
	//seq.Append([]byte(action1), peerKey, "group0", groupKey)

	//fmt.Println(seq)
	assert := assert.New(t)
	assert.True(seq.Verify())

	for i := 0; i < len(actions); i++ {
		pa := seq.GetPeerAction(i)
		action, err := pa.Decrypt(groupKey)
		assert.Nil(err)

		assert.True(bytes.Equal(actions[i], action))
	}

	//pa0 := seq.GetPeerAction(0)
	//pa1 := seq.GetPeerAction(1)
	//
	//fmt.Println(pa0)
	//fmt.Println(pa1)
	//
	//a0, _ := pa0.Decrypt(aesKey)
	//a1, _ := pa1.Decrypt(aesKey)
	//
	//fmt.Println(string(a0))
	//fmt.Println(string(a1))
}


func BenchmarkAppendAction(b *testing.B) {
	peerKey, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println(err)
	}

	crypto.SaveECDSA("peerkey.priv", peerKey)

	groupKey := make([]byte, 32)
	rand.Read(groupKey)
	//fmt.Println(hex.EncodeToString(groupKey))

	//action0 := "This is some random data to be signed"
	//action1 := "Other data"

	//actions := generator.GenerateRandomActions(100000, 100)

	action := generator.GenerateRandomAction(100)
	seq := pas.NewPeerActionSequence()

	b.ResetTimer()

	start := time.Now()
	for i := 0; i < 100000; i++ {
		seq.Append(action, peerKey, "myGroup", groupKey)
	}
	log.Printf("Took %s", time.Since(start))
}