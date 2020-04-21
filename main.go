package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base32"
	"fmt"
	"log"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/sha3"
)

func generate(wg *sync.WaitGroup, re *regexp.Regexp) error {

	for {

		// Generate key pair
		publicKey, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			wg.Done()
			return err
		}

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
		}

		wg.Done()
		return nil
	}

}

func main() {

	// Check if arguments were provided.
	if len(os.Args[1]) == 0 || len(os.Args[2]) == 0 {
		fmt.Print("please provide a <regex> and a <number>")
		os.Exit(1)
	}

	// Set runtime to use all available CPUs.
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Compile regex from first argument.
	re, err := regexp.Compile(os.Args[1])
	if err != nil {
		log.Fatalf("error compiling regex: %v", err)
	}

	// Get the number of desired addreses from second argument.
	numAddresses, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Fatalf("error converting string to int: %v", err)
	}

	// WaitGroup of size equal to desired number of addresses.
	var wg sync.WaitGroup
	wg.Add(numAddresses)

	// For each CPU, run a generate goroutine.
	errChan := make(chan error, 1)
	for i := 0; i < runtime.NumCPU(); i++ {
		go func() { errChan <- generate(&wg, re) }()
	}
	if err = <-errChan; err != nil {
		log.Fatalf("error generating onion address: %v", err)
	}

	// Exit after the desired number of addresses have been found.
	wg.Wait()

}
