package utils

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strconv"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// Salt Length in bytes
	saltlen = 8

	// Key Length in bytes
	keylen = 32

	// IV - Initialization Vector length - minimum as block size
	ivlen = 16

	// Number of iterations used by the pbkdf2 key generations
	iterations = 2000
)

var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unPad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unPad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// ArchiveFile archives file from input
func ArchiveFile(inputPath string, outputPath string) {
	f, err := os.Create(outputPath)
	check(err)
	defer f.Close()

	var writer *gzip.Writer
	var body []byte

	if writer, err = gzip.NewWriterLevel(f, gzip.BestCompression); err != nil {
		log.Fatalln(err)
	}
	defer writer.Close()

	tw := tar.NewWriter(writer)
	defer tw.Close()

	if body, err = ioutil.ReadFile(inputPath); err != nil {
		log.Fatalln(err)
	}

	if body != nil {
		hdr := &tar.Header{
			Name: path.Base(inputPath),
			Mode: int64(0644),
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			println(err)
		}
		if _, err := tw.Write(body); err != nil {
			println(err)
		}
	}
}

// DeleteFile deletes file
func DeleteFile(path string) {
	err := os.Remove(path)
	check(err)
}

func pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

// Encrypt function
func Encrypt(plainstring string, passphrase string) string {
	// Generate SHA256 hex key and iv from passphrase
	hKey := sha256.New()
	hKey.Write([]byte(passphrase))
	hashKey := fmt.Sprintf("%x", hKey.Sum(nil))

	hIv := sha256.New()
	hIv.Write([]byte(hashKey + passphrase))
	iv := []byte(fmt.Sprintf("%x", hIv.Sum(nil)))[:ivlen]

	// Generate Salt - used for key generation
	header := make([]byte, saltlen+aes.BlockSize)
	salt := header[:saltlen]
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err)
	}

	// Generate the salted key that will be used to create new cipher
	saltedKey := pbkdf2.Key([]byte(hashKey), salt, iterations, keylen, sha1.New)

	// Create new aes cipher
	block, err := aes.NewCipher(saltedKey)
	if err != nil {
		panic(err)
	}

	// Pad the string as for AES CBC we need string subject of encryption to be multiple of block size
	paddedstring, _ := pkcs7Pad([]byte(plainstring), block.BlockSize())
	ciphertext := make([]byte, len(paddedstring))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedstring)
	return base64.StdEncoding.EncodeToString(append(salt, ciphertext...))
}

// GetJsonKeyValue retrives json key from a json object
func GetJsonKeyValue(jsonData string, keyName string) (string, error) {
	b := []byte(jsonData)
	var i interface{}
	_ = json.Unmarshal(b, &i)
	p := i.(map[string]interface{})

	keyValue := p[keyName]
	if keyValue == nil {
		return "", fmt.Errorf("THERE IS NO KEYNAME FOR THIS KEYVALUE - %s", keyValue)
	}
	return fmt.Sprintf("%s", p[keyName]), nil
}

// StringInSlice checks if string not in slice
func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// Counts number of strings in string slice
func StringInSliceCount(a string, list []string) int {
	output := 0
	for _, b := range list {
		if b == a {
			output = output + 1
		}
	}
	return output
}

// Check if string slice has duplicates or more strings
func SliceContainsDuplicatesStrings(list []string) bool {
	for _, a := range list {
		if StringInSliceCount(a, list) > 1 {
			return true
		}
	}
	return false
}

// TagInSlice checks if Tag is present in a list of Tags
func TagInSlice(key string, value string, tags []map[string]string) bool {
	for _, b := range tags {
		for keyMap, valueMap := range b {
			if keyMap == key && valueMap == value {
				return true
			}
		}
	}
	return false
}

// GetEnv exports env value or gives default value
func GetEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}

// AgeToUnixTime Helper function to get the Unix Time
func AgeToUnixTime(s string) int64 {
	return time.Now().Unix() - AgeToSeconds(s)
}

// AgeToSeconds extents timeDuration functions from time package
func AgeToSeconds(s string) int64 {
	a := []rune(s)
	numberOfUnits, err := strconv.ParseInt(string(a[0:len(s)-1]), 10, 64)
	if err != nil {
		fmt.Println(err)
	}
	units := string(a[len(s)-1 : len(s)])
	switch units {
	case "s":
		return numberOfUnits
	case "m":
		return numberOfUnits * 60
	case "h":
		return numberOfUnits * 60 * 60
	case "d":
		return numberOfUnits * 60 * 60 * 24
	default:
		// Check if units is a string, if not treat all input as a int64
		if _, err := strconv.Atoi(units); err == nil {
			i, err := strconv.ParseInt(string(a[0:len(s)]), 10, 64)
			if err != nil {
				fmt.Println(err)
			}
			return i * 60 * 60 * 24
		}
		// Retrun Month as default
		return numberOfUnits * 60 * 60 * 24
	}
}
