# proxima-multispam

Multi-sender transaction spammer for Proxima TPS testing. Standalone binary,
extracted from the main [proxima](https://github.com/lunfardo314/proxima)
repo into its own repository.

## Build

This repo depends on a working tree of proxima as a sibling directory
(`replace` directive in `go.mod` points at `../proxima`). With both
checkouts under the same parent (e.g. `~/go/src/github.com/lunfardo314/`):

```
go build -o multispam .
```

## Commands

```
multispam init    # generate sender keys + multispam.yaml
multispam fund    # fund senders from a configured wallet
multispam info    # show sender balances
multispam run     # start the spammer
```

See [docs/multispam.md](docs/multispam.md) for the full design and config
reference.
