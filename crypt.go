// crypt util
//
// Refer to http://github.com/pdevty/crypt for more infomation
//
//	package main
//
//	import (
//		"fmt"
//		"github.com/pdevty/crypt"
//	)
//
//	func main() {
//		crypt := crypt.New([]byte("example key 1234"))
//
//		// encrypt text
//		encrypt, err := crypt.Encrypt([]byte("example data 1234"))
//		if err != nil {
//			panic(err)
//		}
//		fmt.Printf("%x\n", encrypt)
//		// decrypt text
//		decrypt, err := crypt.Decrypt(encrypt)
//		if err != nil {
//			panic(err)
//		}
//		fmt.Printf("%s\n", decrypt)
//
//		// encrypt file
//		if err := crypt.EncryptFile("plain.txt", "encrypt.bin"); err != nil {
//			panic(err)
//		}
//		// decrypt file
//		if err := crypt.DecryptFile("encrypt.bin", "decrypt.txt"); err != nil {
//			panic(err)
//		}
//	}
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"os"
)

// crypt key
type Crypt struct {
	key []byte
}

// crypt new
func New(key []byte) Crypt {
	return Crypt{key: key}
}

// encrypt text
func (c *Crypt) Encrypt(plaintext []byte) ([]byte, error) {

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}

// decrypt text
func (c *Crypt) Decrypt(ciphertext []byte) ([]byte, error) {

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

// encrypt file
func (c *Crypt) EncryptFile(plain, encrypt string) error {

	inFile, err := os.Open(plain)
	if err != nil {
		return err
	}
	defer inFile.Close()

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return err
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	outFile, err := os.OpenFile(encrypt, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()

	writer := &cipher.StreamWriter{S: stream, W: outFile}
	// Copy the input file to the output file, encrypting as we go.
	if _, err := io.Copy(writer, inFile); err != nil {
		return err
	}
	return nil
}

// decrypt file
func (c *Crypt) DecryptFile(encrypt, decrypt string) error {

	inFile, err := os.Open(encrypt)
	if err != nil {
		return err
	}
	defer inFile.Close()

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return err
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	outFile, err := os.OpenFile(decrypt, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()

	reader := &cipher.StreamReader{S: stream, R: inFile}
	// Copy the input file to the output file, decrypting as we go.
	if _, err := io.Copy(outFile, reader); err != nil {
		return err
	}
	return nil
}
