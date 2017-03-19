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
	"strings"
)

func main() {

	// Compile regex from first argument.
	re, _ := regexp.Compile(os.Args[1])

	// Generate new random private key.
	privKey, _ := rsa.GenerateKey(rand.Reader, 1024)

	// Marshall private key to ANS.1 (DER).
	privASN1 := x509.MarshalPKCS1PrivateKey(privKey)

	for {

		// Marshall public key to ASN.1 DER bytes.
		pubASN1, _ := asn1.Marshal(privKey.PublicKey)

		// Let H = H(PK). Let H' = the first 80 bits of H.
		// Generate a 16-character encoding of H', using base32.
		pubSHA1 := sha1.Sum(pubASN1)
		pubBase32 := base32.StdEncoding.EncodeToString(pubSHA1[:10])

		// If a matching address is found...
		if re.MatchString(pubBase32) == true {

			// Print address and iteration info.
			fmt.Println(strings.ToLower(pubBase32) + ".onion")
			fmt.Print("found on iteration ")
			fmt.Println((privKey.E - 65537) / 2)

			// Encode private key as PEM, save to file, and exit.
			privBytes := pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: privASN1,
			})
			ioutil.WriteFile("private_key", privBytes, 0400)
			os.Exit(0)

		}

		// If not matching, increase private key exponent and retry.
		privKey.E = privKey.E + 2

	}
}
