package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/sha3"
)

func generate(wg *sync.WaitGroup, re *regexp.Regexp) {

	for {

		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		checkErr(err)

		onionAddress := encodePublicKey(publicKey)

		// If a matching address is found, save key and notify wait group
		if re.MatchString(onionAddress) == true {
			fmt.Println(onionAddress)
			save(onionAddress, publicKey, expandPrivateKey(privateKey))
			wg.Done()
		}
	}
}

// https://github.com/cathugger/mkp224o/blob/af5a7cfe122ba62e819b92c8b5a662151a284c69/ed25519/ed25519.h#L153-L161
// https://github.com/torproject/torspec/blob/12271f0e6db00dee9600425b2de063e02f19c1ee/rend-spec-v3.txt#L2268-L2327 ??
func expandPrivateKey(privateKey ed25519.PrivateKey) [64]byte {

	hash := sha512.Sum512(privateKey[:32])
	hash[0] &= 248
	hash[31] &= 127
	hash[31] |= 64
	return hash

}

// https://github.com/torproject/torspec/blob/12271f0e6db00dee9600425b2de063e02f19c1ee/rend-spec-v3.txt#L2136-L2158
func encodePublicKey(publicKey ed25519.PublicKey) string {

	// checksum = H(".onion checksum" || pubkey || version)
	var checksumBytes bytes.Buffer
	checksumBytes.Write([]byte(".onion checksum"))
	checksumBytes.Write([]byte(publicKey))
	checksumBytes.Write([]byte{0x03})
	checksum := sha3.Sum256(checksumBytes.Bytes())

	// onion_address = base32(pubkey || checksum || version)
	var onionAddressBytes bytes.Buffer
	onionAddressBytes.Write([]byte(publicKey))
	onionAddressBytes.Write([]byte(checksum[:2]))
	onionAddressBytes.Write([]byte{0x03})
	onionAddress := base32.StdEncoding.EncodeToString(onionAddressBytes.Bytes())

	return strings.ToLower(onionAddress)

}

func save(onionAddress string, publicKey ed25519.PublicKey, privateKey [64]byte) {
	os.MkdirAll(onionAddress, 0700)

	privateKeyFile := append([]byte("== ed25519v1-secret: type0 ==\x00\x00\x00"), privateKey[:]...)
	checkErr(ioutil.WriteFile(onionAddress+"/hs_ed25519_secret_key", privateKeyFile, 0600))

	publicKeyFile := append([]byte("== ed25519v1-public: type0 ==\x00\x00\x00"), []byte{0x00, 0x00, 0x00}...)
	checkErr(ioutil.WriteFile(onionAddress+"/hs_ed25519_public_key", publicKeyFile, 0600))

	checkErr(ioutil.WriteFile(onionAddress+"/hostname", []byte(onionAddress+".onion"), 0600))
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {

	// Set runtime to use all available CPUs.
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Compile regex from first argument.
	re, _ := regexp.Compile(os.Args[1])

	// Get the number of desired addreses from second argument.
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
