build() {
  go mod download
  GOAMD64=v3 go build -tags release -o ./oniongen
}

update_libs() {
  go get -u
  go mod tidy
}

help() {
  go get -u
  echo "build update_libs"
}

progname=$(basename $0)
subcommand=$1
case $subcommand in
    "" | "-h" | "--help")
        help
        ;;
    *)
        shift
        echo "Executing: $subcommand"
        ${subcommand} "$@"
        if [ $? = 127 ]; then
            echo "Error: '$subcommand' is not a known subcommand." >&2
            help
            exit 1
        fi
        ;;
esac
