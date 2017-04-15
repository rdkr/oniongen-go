# oniongen-go

v3 .onion vanity URL generator written in Go

## Usage

```
go run main.go <regex> <number>

    regex   regex pattern addresses should match, consisiting of: A-Z, 2-7
    number  number of matching addresses to generate before exiting
```

## Example

```
go run main.go "^TEST" 5

    generate 5 onion addresses starting with "test"
```
