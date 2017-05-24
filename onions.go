/*
Search the RSA 1024 keyspace for Tor onion addresses that start with dictionary
words.

The results are stored in ./keys named by the onion address that they produce.
*/

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base32"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"
)

/*
Create onion address by base-32 encoding a SHA1 hash of the first half of a
new private RSA key.
*/
func RandOnion() (*rsa.PrivateKey, string) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	der, _ := asn1.Marshal(key.PublicKey)
	hash := sha1.Sum(der)
	half := hash[:len(hash)/2]
	onion := base32.StdEncoding.EncodeToString(half)
	return key, onion
}

/*
Result structure is private key + onion pair.
*/
type Result struct {
	key   *rsa.PrivateKey
	onion string
}

/*
Endlessly generate random onion addresses and check them against the words array
looking for prefix matches.
*/
func Search(words []string, results chan *Result) {
	for {
		key, onion := RandOnion()
		for _, word := range words {
			if strings.HasPrefix(onion, word) {
				results <- &Result{key, strings.ToLower(onion)}
				break
			}
		}
	}
}

/*
Read a local dictionary file.
*/
func readDictFile(dictFile string) []string {
	bytes, _ := ioutil.ReadFile(dictFile)
	body := string(bytes)
	return strings.Fields(body)
}

/*
Read dictionary file from a URL.
*/
func readDictUrl(dictUrl string) []string {
	res, _ := http.Get(dictUrl)
	bytes, _ := ioutil.ReadAll(res.Body)
	body := string(bytes)
	return strings.Fields(body)
}

func main() {

	var minSize int
	flag.IntVar(&minSize, "min", 3, "Minimum word size")

	var dictFile string
	flag.StringVar(&dictFile, "file", "", "Path to dictionary file")

	var dictUrl string
	flag.StringVar(&dictUrl, "url", "", "URL of dictionary file")

	flag.Parse()

	var words []string

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
	results := make(chan *Result)
	for i := 0; i < runtime.NumCPU(); i++ {
		go Search(words, results)
	}

	os.MkdirAll("./keys", os.ModePerm)

	for result := range results {
		fmt.Println(result.onion)
		der := x509.MarshalPKCS1PrivateKey(result.key)
		b64 := base64.StdEncoding.EncodeToString(der)
		f, _ := os.Create("./keys/" + result.onion + ".onion")
		f.WriteString("RSA1024:")
		f.WriteString(b64)
		f.Sync()
	}
}
