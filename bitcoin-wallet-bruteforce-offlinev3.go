package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
	"crypto/sha256"
	"sync/atomic"
	"math/big"
)

// Declare global counters
var counter int64
var matchCounter int64

func readAddresses(filePath string) (map[string]bool, error) {
	addresses := make(map[string]bool)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		addresses[scanner.Text()] = true
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return addresses, nil
}

func generateKeyAndAddress() (string, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	publicKey := privateKey.PublicKey
	address, err := publicKeyToAddress(publicKey)
	if err != nil {
		return "", "", err
	}

	return hex.EncodeToString(privateKey.D.Bytes()), address, nil
}

func publicKeyToAddress(publicKey ecdsa.PublicKey) (string, error) {
	pubKeyBytes := append(publicKey.X.Bytes(), publicKey.Y.Bytes()...)

	sha256Hash := sha256.New()
	sha256Hash.Write(pubKeyBytes)
	sha256Result := sha256Hash.Sum(nil)

	ripemd160Hash := ripemd160.New()
	ripemd160Hash.Write(sha256Result)
	ripemd160Result := ripemd160Hash.Sum(nil)

	networkVersion := byte(0x00)
	addressBytes := append([]byte{networkVersion}, ripemd160Result...)
	checksum := sha256Checksum(addressBytes)
	fullAddress := append(addressBytes, checksum...)

	return base58.Encode(fullAddress), nil
}

func sha256Checksum(input []byte) []byte {
	firstSHA := sha256.New()
	firstSHA.Write(input)
	result := firstSHA.Sum(nil)

	secondSHA := sha256.New()
	secondSHA.Write(result)
	finalResult := secondSHA.Sum(nil)

	return finalResult[:4]
}

func worker(id int, wg *sync.WaitGroup, mutex *sync.Mutex, outputFile string, btcAddresses map[string]bool) {
	defer wg.Done()

	// Add the specific private key you want to check
	specificPrivateKey := "03902e4f09664bc177fe4e090dcd9906b432b50f15fb6151984475c1c75c35b6"

	// Convert the specific private key from a string to bytes
	specificPrivateKeyBytes, err := hex.DecodeString(specificPrivateKey)
	if err != nil {
		log.Printf("Worker %d: Failed to decode specific private key: %s", id, err)
		return
	}

	// Create an ecdsa.PrivateKey object from the bytes
	specificPrivateKeyECDSA := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(specificPrivateKeyBytes[:32]),
			Y:     new(big.Int).SetBytes(specificPrivateKeyBytes[32:]),
		},
		D: new(big.Int).SetBytes(specificPrivateKeyBytes),
	}

	// Generate the public key from the specific private key
	specificPublicKeyECDSA := &specificPrivateKeyECDSA.PublicKey

	// Generate the public address from the specific public key
	specificPublicAddress, err := publicKeyToAddress(*specificPublicKeyECDSA)
	if err != nil {
		log.Printf("Worker %d: Failed to generate public address from specific private key: %s", id, err)
		return
	}

	// Check if the specific public address exists in the BTC addresses
	if _, exists := btcAddresses[specificPublicAddress]; exists {
		fmt.Printf("Specific Private Key Found! Privatekey: %s Publicaddress: %s\n", specificPrivateKey, specificPublicAddress)

		mutex.Lock()
		file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Worker %d: Failed to open file: %s", id, err)
			mutex.Unlock()
			return
		}

		if _, err := file.WriteString(fmt.Sprintf("%s:%s\n", specificPrivateKey, specificPublicAddress)); err != nil {
			log.Printf("Worker %d: Failed to write to file: %s", id, err)
		}
		file.Close()
		mutex.Unlock()
	}

	for {
		privateKey, publicAddress, err := generateKeyAndAddress()
		if err != nil {
			log.Printf("Worker %d: Failed to generate key and address: %s", id, err)
			continue
		}

		// Increment the counter
		atomic.AddInt64(&counter, 1)

		if counter % 1000000 == 0 {
			fmt.Printf("Count: %dM Matches: %d\n", counter/1000000, matchCounter)
		}

		if _, exists := btcAddresses[publicAddress]; exists {
			// Increment the match counter
			atomic.AddInt64(&matchCounter, 1)
			fmt.Printf("Match Found! Privatekey: %s Publicaddress: %s\n", privateKey, publicAddress)

			mutex.Lock()
			file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Printf("Worker %d: Failed to open file: %s", id, err)
				mutex.Unlock()
				continue
			}

			if _, err := file.WriteString(fmt.Sprintf("%s:%s\n", privateKey, publicAddress)); err != nil {
				log.Printf("Worker %d: Failed to write to file: %s", id, err)
			}
			file.Close()
			mutex.Unlock()
		}
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: ./bitcoin-wallet-bruteforce-offlinev4 <threads> <output-file.txt> <btc-address-file.txt>")
		os.Exit(1)
	}

	numThreads, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalf("Invalid number of threads: %s", err)
	}

	outputFile := os.Args[2]
	btcAddressesFile := os.Args[3]

	// Read the BTC addresses from the file
	btcAddresses, err := readAddresses(btcAddressesFile)
	if err != nil {
		log.Fatalf("Failed to read BTC addresses: %s", err)
	}

	var wg sync.WaitGroup
	var mutex sync.Mutex

	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go worker(i, &wg, &mutex, outputFile, btcAddresses)
	}

	wg.Wait()
}
