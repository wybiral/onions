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
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"
)

func KeyToOnion(key *rsa.PrivateKey) string {
	pub := key.Public()
	der, _ := x509.MarshalPKIXPublicKey(pub)
	hashed := sha1.Sum(der[22:])
	halfed := hashed[:len(hashed)/2]
	return base32.StdEncoding.EncodeToString(halfed)
}

func RandOnion() (*rsa.PrivateKey, string) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	onion := KeyToOnion(key)
	return key, onion
}

func GetWords(wordListUrl string) []string {
	res, _ := http.Get(wordListUrl)
	bytes, _ := ioutil.ReadAll(res.Body)
	body := string(bytes)
	words := strings.Fields(body)
	out := []string{}
	for _, word := range words {
		// Limit to words larger than 3 characters
		if len(word) > 3 {
			out = append(out, strings.ToUpper(word))
		}
	}
	return out
}

type Result struct {
	key   *rsa.PrivateKey
	onion string
}

func Search(words []string, results chan *Result) {
	for {
		key, onion := RandOnion()
		for _, word := range words {
			if strings.HasPrefix(onion, word) {
				results <- &Result{key, strings.ToLower(onion)}
			}
		}
	}
}

func main() {
	words := GetWords("http://www.mit.edu/~ecprice/wordlist.10000")
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
