package main

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"src\crypto/ed25519"
	"src\crypto/sha3"
)

func generate(wg *sync.WaitGroup, re *regexp.Regexp) {

	for {

		// Generate key pair
		publicKey, _, _ := ed25519.GenerateKey(nil)

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

		// If a matching address is found, save key and notify wait group
		if re.MatchString(onionAddress) == true {
			fmt.Println(strings.ToLower(onionAddress) + ".onion")
			wg.Done()
		}
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
