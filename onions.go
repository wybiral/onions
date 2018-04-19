// Generate Tor vanity onions from a dictionary file.
// The results are stored in ./keys

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base32"
	"encoding/base64"
	"flag"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"
	"log"
)

type Result interface {
	Onion() string
	PrivateKey() string
}

type rsaResult struct {
	onion      string
	privateKey *rsa.PrivateKey
}

// RSA onions are created by:
// 1. Generate RSA 1024 key pair
// 2. DER encode public key
// 3. SHA-1 hash the DER encoded public key
// 4. Base32 encode the first half SHA-1 hash
func randRsaResult() Result {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	der, _ := asn1.Marshal(key.PublicKey)
	hash := sha1.Sum(der)
	half := hash[:len(hash)/2]
	onion := base32.StdEncoding.EncodeToString(half)
	return &rsaResult{onion: onion, privateKey: key}
}

func (r *rsaResult) Onion() string {
	return r.onion
}

func (r *rsaResult) PrivateKey() string {
	der := x509.MarshalPKCS1PrivateKey(r.privateKey)
	b64 := base64.StdEncoding.EncodeToString(der)
	return "RSA1024:" + b64
}

type ed25519Result struct {
	onion      string
	privateKey ed25519.PrivateKey
}

func randEd25519Result() Result {
	pub, pri, _ := ed25519.GenerateKey(rand.Reader)
	return &ed25519Result{onion: ed25519ToOnion(pub), privateKey: pri}
}

func (r *ed25519Result) Onion() string {
	return r.onion
}

func (r *ed25519Result) PrivateKey() string {
	h := sha512.Sum512(r.privateKey[:32])
	// Set bits so that h[:32] is private scalar "a"
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	// Since h[32:] is RH, h is now (a || RH)
	b64 := base64.StdEncoding.EncodeToString(h[:])
	return "ED25519-V3:" + b64
}

func ed25519ToOnion(pub ed25519.PublicKey) string {
	// Construct onion address base32(publicKey || checkdigits || version)
	checkdigits := ed25519Checkdigits(pub)
	combined := pub[:]
	combined = append(combined, checkdigits...)
	combined = append(combined, 0x03)
	return base32.StdEncoding.EncodeToString(combined)
}

func ed25519Checkdigits(pub ed25519.PublicKey) []byte {
	// Calculate checksum sha3(".onion checksum" || publicKey || version)
	checkstr := []byte(".onion checksum")
	checkstr = append(checkstr, pub...)
	checkstr = append(checkstr, 0x03)
	checksum := sha3.Sum256(checkstr)
	return checksum[:2]
}

// Endlessly generate random onion addresses and check them against the words
// array looking for prefix matches.
func Search(keyFunc func()Result, words []string, results chan Result) {
	for {
		r := keyFunc()
		onion := r.Onion()
		for _, word := range words {
			if strings.HasPrefix(onion, word) {
				results <- r
				break
			}
		}
	}
}

// Read a local dictionary file.
func readDictFile(dictFile string) []string {
	bytes, _ := ioutil.ReadFile(dictFile)
	body := string(bytes)
	return strings.Fields(body)
}

// Read dictionary file from a URL.
func readDictUrl(dictUrl string) []string {
	res, _ := http.Get(dictUrl)
	bytes, _ := ioutil.ReadAll(res.Body)
	body := string(bytes)
	return strings.Fields(body)
}

func main() {

	var minSize int
	flag.IntVar(&minSize, "min", 4, "Minimum word size")

	var dictFile string
	flag.StringVar(&dictFile, "file", "", "Path to dictionary file")

	var dictUrl string
	flag.StringVar(&dictUrl, "url", "", "URL of dictionary file")

	var keyType string
	flag.StringVar(&keyType, "key", "rsa", "Type of key (rsa or ed25519)")

	flag.Parse()
	
	var words []string
	var keyFunc func()Result

	keyType = strings.ToLower(keyType)
	if keyType == "ed25519" {
		keyFunc = randEd25519Result
	} else if (keyType == "rsa") {
		keyFunc = randRsaResult
	} else {
		log.Fatal("Unrecognized key type: " + keyType)
	}

	if len(dictFile) == 0 && len(dictUrl) == 0 {
		fmt.Println("No dictionary supplied. See --help for usage.")
		return
	} else {
		fmt.Printf("Loading dictionary... ")
		if len(dictFile) > 0 {
			words = readDictFile(dictFile)
		} else if len(dictUrl) > 0 {
			words = readDictUrl(dictUrl)
		}
	}

	// Filter by minimum size and convert to uppercase
	var filtered []string
	for _, word := range words {
		if len(word) >= minSize {
			filtered = append(filtered, strings.ToUpper(word))
		}
	}
	words = filtered

	fmt.Println(len(words), "words found.")
	fmt.Println("Searching...")

	// Start up the goroutines
	results := make(chan Result)
	for i := 0; i < runtime.NumCPU(); i++ {
		go Search(keyFunc, words, results)
	}

	os.MkdirAll("./keys", os.ModePerm)

	for r := range results {
		onion := strings.ToLower(r.Onion())
		privateKey := r.PrivateKey()
		fmt.Println(onion)
		f, _ := os.Create("./keys/" + onion + ".onion")
		f.WriteString(privateKey)
		f.Sync()
	}
}
