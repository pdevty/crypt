# crypt [![GoDoc](https://godoc.org/github.com/pdevty/crypt?status.svg)](https://godoc.org/github.com/pdevty/crypt)

crypt util

## Installation

execute:

    $ go get github.com/pdevty/crypt

## Usage

```go
package main

import (
	"fmt"
	"github.com/pdevty/crypt"
)

func main() {
	crypt := crypt.New([]byte("example key 1234"))

	// encrypt text
	encrypt, err := crypt.Encrypt([]byte("example data 1234"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", encrypt)
	// decrypt text
	decrypt, err := crypt.Decrypt(encrypt)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", decrypt)

	// encrypt file
	if err := crypt.EncryptFile("plain.txt", "encrypt.bin"); err != nil {
		panic(err)
	}
	// decrypt file
	if err := crypt.DecryptFile("encrypt.bin", "decrypt.txt"); err != nil {
		panic(err)
	}
}
```

Refer to [godoc](http://godoc.org/github.com/pdevty/crypt) for more infomation.

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
