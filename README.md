# oniongen-go

v3 .onion address vanity URL generator written in Go.

This implementation generates random ed25519 keys across all CPU cores.
The ed25519 public key is converted to a Tor v3 .onion address which is then compared to a user supplied regex to find a vanity URL.
If the regex for the .onion address matches, the secret key is expanded for use by Tor and the public key, secret key, and hostname are written to file in a new directory named for the .onion address.
The program terminates when the user supplied number of addresses have been generated.

## Usage

```
go run main.go <regex> <number>

    regex   regex pattern addresses should match, consisiting of: a-z, 2-7
    number  number of matching addresses to generate before exiting
```

## Example

```
go run main.go "^test" 5

    generate 5 onion addresses starting with "test"
```

## References
- Onion Addresses are defined in [Tor Rendezvous Specification - Version 3](https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt)
- public key -> onion: https://github.com/torproject/torspec/blob/12271f0e6db00dee9600425b2de063e02f19c1ee/rend-spec-v3.txt#L2136-L2158
- secret key expansion:
    - implementation in mkp224o: https://github.com/cathugger/mkp224o/blob/af5a7cfe122ba62e819b92c8b5a662151a284c69/ed25519/ed25519.h#L153-L161
    - possibly related: https://github.com/torproject/torspec/blob/12271f0e6db00dee9600425b2de063e02f19c1ee/rend-spec-v3.txt#L2268-L2327 ??
