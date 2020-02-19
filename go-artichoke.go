package main

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/qbetti/go-artichoke/artichoke/pas"
	"github.com/urfave/cli"
	"log"
	"os"
	"sort"
)

func main() {
	peerFlag := &cli.StringFlag{
		Name:     "peer",
		Aliases:  []string{"p"},
		Usage:    "Identity of the peer performing the action to append",
		Required: true,
	}

	peerKeyFlag := &cli.StringFlag{
		Name:     "peer-key",
		Aliases:  []string{"pk"},
		Usage:    "File containing the private key of the peer",
		Required: true,
	}

	groupFlag := &cli.StringFlag{
		Name:     "group",
		Aliases:  []string{"g"},
		Usage:    "Group the action is to be performed on behalf of",
		Required: true,
	}

	groupKeyFlag := &cli.StringFlag{
		Name:     "group-key",
		Aliases:  []string{"gk"},
		Usage:    "File containing the symmetric key of the group",
		Required: true,
	}

	sequenceFlag := &cli.StringFlag{
		Name:     "sequence",
		Aliases:  []string{"s"},
		Usage:    "File containing the sequence or that will contain the sequence",
		Required: true,
	}

	actionFlag := &cli.StringFlag{
		Name:     "action",
		Aliases:  []string{"a"},
		Usage:    "Action to be appended to the sequence",
		Required: true,
	}

	app := &cli.App{
		Name:    "go-artichoke",
		Usage:   "A CLI application written in Go to manipulate and explore peer-action sequences",
		Version: "1.0",
		Commands: []*cli.Command{
			{
				Name:  "add",
				Usage: "add an action to an existing or new sequence",
				Flags: []cli.Flag{
					peerFlag,
					peerKeyFlag,
					groupFlag,
					groupKeyFlag,
					sequenceFlag,
					actionFlag,
				},
				Action: func(c *cli.Context) error {
					return addAction(c.String(peerFlag.Name),
						c.String(peerKeyFlag.Name),
						c.String(groupFlag.Name),
						c.String(groupKeyFlag.Name),
						c.String(actionFlag.Name),
						c.String(sequenceFlag.Name))
				},
			},
			{
				Name:  "verify",
				Usage: "verify the integrity of a sequence",
				Flags: []cli.Flag{
					sequenceFlag,
				},
				Action: func(c *cli.Context) error {
					return verify(c.String(sequenceFlag.Name))
				},
			},
			{
				Name:  "list",
				Usage: "list all the peer-actions in the sequence",
				Flags: []cli.Flag{
					sequenceFlag,
				},
				Action: func(c *cli.Context) error {
					return list(c.String(sequenceFlag.Name))
				},
			},
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func addAction(peer string, peerKeyFilePath string, group string, groupKey string, action string, sequenceFilePath string) error {
	fmt.Println("Peer", peer,
		"with public key", peerKeyFilePath,
		"adds the action", action,
		"on behalf of group", group,
		"and encrypted with group key", groupKey,
		"in the sequenceFilePath in file", sequenceFilePath)

	if !fileExists(sequenceFilePath) {
		fmt.Println("File", sequenceFilePath, "does not exist.")
		_, err := os.Create(sequenceFilePath)
		if err != nil {
			log.Fatal("Could not create file", sequenceFilePath)
			os.Exit(-1)
		}
		fmt.Println("Created a new file for the sequenceFilePath.")
	}
	seq, err := pas.LoadFromFile(sequenceFilePath)

	privateKey, err := crypto.LoadECDSA(peerKeyFilePath)
	if err != nil {
		log.Fatal(err)
		os.Exit(-1)
	}

	groupKeyBytes, err := hex.DecodeString(groupKey)
	if err != nil {
		log.Fatal(err)
		os.Exit(-1)
	}
	seq.Append([]byte(action), privateKey, group, groupKeyBytes)

	fmt.Println("Action has been added to the sequence")
	seq.SaveToFile(sequenceFilePath)
	fmt.Println("Sequence file has been updated")

	return nil
}

func verify(sequence string) error {
	fmt.Println("I verify the sequence stored in the file", sequence)
	seq, err := pas.LoadFromFile(sequence)
	if err != nil {
		return err
	}

	isValid, violations := seq.Verify()

	if isValid {
		fmt.Println("Sequence has been verified!")
	} else {
		fmt.Println("Sequence is NOT valid. See the following violations:")
		for _, violation := range violations {
			fmt.Println(violation.Error())
		}
	}

	return nil
}

func list(sequence string) error {
	seq, err := pas.LoadFromFile(sequence)
	if err != nil {
		return err
	}

	fmt.Println("Sequence contains the following peer-actions:")

	for i := 0; i < seq.GetSize(); i++ {
		pa := seq.GetPeerAction(i)
		fmt.Println(pa.String())
	}

	return nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
