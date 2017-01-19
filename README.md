# onions
Generate Tor vanity onions with Go

### Example using online dictionary file:

```go run onions.go --url=http://www.mit.edu/~ecprice/wordlist.10000```

### Example using local dictionary file:

```go run onions.go --file=/path/to/dict.txt```

### For command line help:

```go run onions.go --help```

### Hidden services

For an easy way to start a hidden service from a generated key, use the Python module: [shh](https://github.com/wybiral/shh)

```
pip install shh
python -m shh -p PORT_TO_SERVE --key=/Path/To/Keyfile.onion
```
