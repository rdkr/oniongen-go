package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"sync"

	"golang.org/x/crypto/sha3"
)

const b32Lower = "abcdefghijklmnopqrstuvwxyz234567"

var b32Enc = base32.NewEncoding(b32Lower).WithPadding(base32.NoPadding)

func generate(wg *sync.WaitGroup, re *regexp.Regexp) {
	for {
		publicKey, secretKey, err := ed25519.GenerateKey(nil)
		checkErr(err)

		onionAddress := encodePublicKey(publicKey)

		// If a matching address is found, save key and notify wait group
		if re.MatchString(onionAddress) == true {
			fmt.Println(onionAddress)
			save(onionAddress, publicKey, expandSecretKey(secretKey))
			wg.Done()
		}
	}
}

func expandSecretKey(secretKey ed25519.PrivateKey) [64]byte {
	hash := sha512.Sum512(secretKey[:32])
	// clamp the blinding factor 'h' according to the ed25519 spec
	hash[0] &= 248
	hash[31] &= 127
	hash[31] |= 64
	return hash
}

func encodePublicKey(publicKey ed25519.PublicKey) string {
	// checksum = H(".onion checksum" || pubkey || version)
	var checksumBytes bytes.Buffer
	checksumBytes.Write([]byte(".onion checksum"))
	checksumBytes.Write(publicKey)
	checksumBytes.Write([]byte{0x03})
	checksum := sha3.Sum256(checksumBytes.Bytes())

	// onion_address = base32(pubkey || checksum || version)
	var onionAddressBytes bytes.Buffer
	onionAddressBytes.Write(publicKey)
	onionAddressBytes.Write(checksum[:2])
	onionAddressBytes.Write([]byte{0x03})
	onionAddress := b32Enc.EncodeToString(onionAddressBytes.Bytes())

	return onionAddress
}

func save(onionAddress string, publicKey ed25519.PublicKey, secretKey [64]byte) {
	checkErr(os.MkdirAll(onionAddress, 0700))

	secretKeyFile := append([]byte("== ed25519v1-secret: type0 ==\x00\x00\x00"), secretKey[:]...)
	checkErr(os.WriteFile(onionAddress+"/hs_ed25519_secret_key", secretKeyFile, 0600))

	publicKeyFile := append([]byte("== ed25519v1-public: type0 ==\x00\x00\x00"), publicKey...)
	checkErr(os.WriteFile(onionAddress+"/hs_ed25519_public_key", publicKeyFile, 0600))

	checkErr(os.WriteFile(onionAddress+"/hostname", []byte(onionAddress+".onion\n"), 0600))
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	// Set runtime to use all available CPUs.
	runtime.GOMAXPROCS(runtime.NumCPU())

	prefix := os.Args[1]
	// Compile regex from first argument.
	re, _ := regexp.Compile(prefix)

	// Get the number of desired addresses from second argument.
	numAddresses, _ := strconv.Atoi(os.Args[2])

	// WaitGroup of size equal to desired number of addresses
	var wg sync.WaitGroup
	wg.Add(numAddresses)

	// For each CPU, run a generate goroutine
	for i := 0; i < runtime.NumCPU(); i++ {
		go generate(&wg, re)
	}

	// Exit after the desired number of addresses have been found.
	wg.Wait()
}
