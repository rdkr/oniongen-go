// Generates a Tor RSA private key whose .onion SLD matches
// the regex provided as an argument (all-caps).

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

func save(privKey *rsa.PrivateKey, pubBase32 string) {

	// Print address and iteration info.
	fmt.Printf("%v.onion found on iteration %v\n",
		strings.ToLower(pubBase32), (privKey.E-65537)/2)

	// Marshall private key to ANS.1 (DER).
	privASN1 := x509.MarshalPKCS1PrivateKey(privKey)

	// Encode private key as PEM, save to file, and exit.
	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privASN1,
	})

	// Write key to file.
	ioutil.WriteFile("private_key-"+strings.ToLower(pubBase32), privBytes, 0400)

}

func generate(wg *sync.WaitGroup, re *regexp.Regexp) {

	// Generate new random private key.
	privKey, _ := rsa.GenerateKey(rand.Reader, 1024)

	for {

		// Marshall public key to ASN.1 DER bytes.
		pubASN1, _ := asn1.Marshal(privKey.PublicKey)

		// Let H = H(PK). Let H' = the first 80 bits of H.
		// Generate a 16-character encoding of H', using base32.
		pubSHA1 := sha1.Sum(pubASN1)
		pubBase32 := base32.StdEncoding.EncodeToString(pubSHA1[:10])

		// If a matching address is found, save key and notify wait group
		if re.MatchString(pubBase32) == true {
			save(privKey, pubBase32)
			wg.Done()
		}

		// If not matching, increase private key exponent and retry.
		privKey.E = privKey.E + 2

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
