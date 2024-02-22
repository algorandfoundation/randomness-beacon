package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/mnemonic"
	"github.com/ori-shem-tov/vrf-oracle/cmd/daemon"
	"github.com/ori-shem-tov/vrf-oracle/tools"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	tools.SetLogger(logLevelEnv)

	CreateSecretsCmd.Flags().Uint64Var(&startingRound, "starting-round", 0,
		"the round to start scanning from (optional. default: current round)")

}

var CreateSecretsCmd = &cobra.Command{
	Use:   "create-secrets",
	Short: "creates the secrets for the VRF oracle",
	Run: func(cmd *cobra.Command, args []string) {
		err := tools.TestEnvironmentVariables(AlgodAddress)
		if err != nil {
			log.Error(err)
			return
		}
		algodClient, err := tools.InitClients(AlgodAddress, AlgodToken)
		if err != nil {
			log.Error(err)
			return
		}
		startingRound, err = daemon.GetStartingRound(startingRound, algodClient)
		if err != nil {
			log.Error(err)
			return
		}

		vrfAccount := crypto.GenerateAccount()

		vrfPrivateKeyHex := hex.EncodeToString(vrfAccount.PrivateKey)

		vrfProof, err := daemon.GetVRFProofForRound(algodClient, startingRound, vrfAccount.PrivateKey)
		if err != nil {
			log.Error(err)
			return
		}

		vrfProofB64 := base64.StdEncoding.EncodeToString(vrfProof)

		serviceAccount := crypto.GenerateAccount()

		fmt.Println("Public keys and VRF proof:")
		fmt.Printf("{\"startingRound\": %d, \"vrfPublicKey\": \"%s\", \"vrfProof\": \"%s\", \"servicePublicKey\": \"%s\"}", startingRound, vrfAccount.Address, vrfProofB64, serviceAccount.Address)
		fmt.Println()

		serviceMnemonic, err := mnemonic.FromPrivateKey(serviceAccount.PrivateKey)
		if err != nil {
			log.Error(err)
			return
		}

		fmt.Println("Press Enter to show secrets")
		fmt.Scanln()

		fmt.Printf("{\"vrfKey\": \"%s\", \"serviceMnemonic\": \"%s\"}", vrfPrivateKeyHex, serviceMnemonic)
		fmt.Println()

	},
}
