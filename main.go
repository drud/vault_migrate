package main

import (
	"log"
	vaultAPI "github.com/hashicorp/vault/api"
	"flag"
	"time"
	"math/rand"
	"bufio"
	"os"
	"fmt"
	"reflect"
)


// Simple count of how many secrets handled
var itemCount int

func main() {

	// Initialize random number generator for text destroyer
	rand.Seed(int64(time.Nanosecond));

	var sourceVaultAddr, sourceToken, sourceRoot, targetVaultAddr, targetToken, targetRoot string
	var deleteOnly, readOnly, destroyValues bool
	flag.StringVar(&sourceVaultAddr, "sourceVaultAddr", "", "vault_addr for the copy-from vault, like https://example.com:8200")
	flag.StringVar(&sourceToken, "sourceToken", "", "Token for sourceVaultAddr - best to have read privs only")
	flag.StringVar(&sourceRoot, "sourceRoot", "/secret/", "Root in source tree to start copying from")
	flag.StringVar(&targetVaultAddr, "targetVaultAddr", "", "vault_addr for the copy-to vault, like https://example2.com:8200")
	flag.StringVar(&targetToken, "targetToken", "", "Token for targetVaultAddr - must have write privs")
	flag.StringVar(&targetRoot, "targetRoot", "/secret/copy2", "Root in target tree to start copying to")
	flag.BoolVar(&deleteOnly, "deleteOnly", false, "Set to true to delete from targetRoot on targetVaultAddr")
	flag.BoolVar(&readOnly, "readOnly", false, "Set to true to recursively reaad from targetRoot on targetVaultAddr - for performance and load testing")
	flag.BoolVar(&destroyValues, "destroyValues", true, "Set to false to turn off the value-destroying function")
	flag.Parse()


	switch {
	case readOnly == true:
		if targetVaultAddr == "" || targetRoot == "" {
			log.Fatal("-targetVaultAddr and -targetRoot must be set in order to read from target")
		}
		fmt.Printf("Reading recursively from %s:%s\n", targetVaultAddr, targetRoot)

	case deleteOnly == true:
		if targetVaultAddr == "" || targetRoot == "" {
			log.Fatal("-targetVaultAddr and -targetRoot must be set in order to delete from target")
		}
		fmt.Printf("Deleting from %s:%s\n", targetVaultAddr, targetRoot)

	default:  // Copy - basic usage of the utility
		if sourceVaultAddr == "" || sourceRoot == "" || targetVaultAddr == "" || targetRoot == "" {
			log.Fatal("both vault and root must be set in order to copy")
		}

		fmt.Printf("Copying from %s:%s to %s:%s\n", sourceVaultAddr, sourceRoot, targetVaultAddr, targetRoot)
		if destroyValues {
			fmt.Printf("Secret values will be destroyed on write because destroyValues == true\n")
		} else {
			fmt.Printf("Secret values will be copied as-is, make sure target is secure.\n")
		}
	}
	sourceVault := getVault(sourceToken, sourceVaultAddr)
	targetVault := getVault(targetToken, targetVaultAddr)

	confirm("Are you sure you want to continue? [y/n]")

	if (deleteOnly) {
		recursiveDelete(targetVault, targetRoot);
		return
	} else if (readOnly) {
		recursiveRead(targetVault, targetRoot)
	} else {
		recursiveCopy(sourceVault, sourceRoot, targetVault, targetRoot, destroyValues)
	}
}

// return string of same length, but completely destroyed and unrecoverable
func destroyText(plainText string) string {
	var newText string;
	for i:=0; i<len(plainText); i++ {
		newText = newText + string(plainText[i] ^ byte(rand.Int()))
	}
	return newText
}

// Simple confirmation prompt. 'y\n' is required to continue
func confirm(prompt string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt + ":")
	response, _ := reader.ReadString('\n')
	if (response != "y\n") {
		log.Fatal("Use 'y' to continue")
	}
}

// Recursively copy secrets from one vault to another
func recursiveCopy(sourceVault vaultAPI.Logical, sourceKey string, targetVault vaultAPI.Logical, targetKey string, destroyValues bool) {

	result := list(sourceVault, sourceKey)

	for _, key := range result  {

		fullSourceKey := sourceKey + "/" + key
		lastChar := fullSourceKey[len(fullSourceKey)-1:]

		fullTargetKey := targetKey + "/" + key

		// If the key ends in / we have to recursively copy its keys
		if lastChar == "/" {
			// Remove the trailing slash
			fullTargetKey = fullTargetKey[0:len(fullTargetKey)-1]
			fullSourceKey = fullSourceKey[0:len(fullSourceKey)-1]
			recursiveCopy(sourceVault, fullSourceKey, targetVault, fullTargetKey, destroyValues)
			continue
		}

		value, err := sourceVault.Read(fullSourceKey)
		if (err != nil) {
			log.Panic(err)
		}

		// Default case is we'll destroy all values, leaving keys untouched - to prevent
		// accidental disclosure before actual production migration.
		if destroyValues {
			for k, v := range value.Data {
				// Only destroy string value types
				if _, ok := v.(string); ok {
					value.Data[k] = destroyText(v.(string))
					//log.Printf("k=%s value destroyed.", k)
				} else {
					value.Data[k] = "Complex value replaced"
					log.Printf("Replacing complex value for key=%s because value is of type %s", k, reflect.TypeOf(v))
				}
			}
		}

		_, err = targetVault.Write(fullTargetKey, value.Data)
		if (err != nil) {
			log.Panic(err)
		}
		itemCount = itemCount +1
		log.Printf("Wrote key from source=%v to target=%v count=%d", fullSourceKey, fullTargetKey, itemCount)

	}
}


// Recursively read secrets from targetVault
func recursiveRead(targetVault vaultAPI.Logical, targetKey string) {

	result := list(targetVault, targetKey)

	for _, key := range result  {


		fullTargetKey := targetKey + "/" + key
		lastChar := fullTargetKey[len(fullTargetKey)-1:]

		// If the key ends in / we have to recursively read its keys
		if lastChar == "/" {
			// Remove the trailing slash
			fullTargetKey = fullTargetKey[0:len(fullTargetKey)-1]
			recursiveRead(targetVault, fullTargetKey)
			continue
		}

		_, err := targetVault.Read(fullTargetKey)
		if (err != nil) {
			log.Panic(err)
		}

		itemCount = itemCount +1
		log.Printf("Read key from source=%v count=%d", fullTargetKey, itemCount)

	}
}


// Return keys under a pat as array of strings
func list(vault vaultAPI.Logical, path string) []string {
	list, err := vault.List(path)
	var resultList []string

	if err != nil {
		log.Fatalf("Error: %v", err.Error())
	}

	// Check for non-empty result of list - it might not if there was nothing in list
	if list != nil {
		if _, ok := list.Data["keys"].([]interface{}); ok {
			for _, element := range (list.Data["keys"].([]interface{})) {
				resultList = append(resultList, element.(string))
			}
		}
	}

	return resultList
}


// Get vault object using token + vault_addr
func getVault(token string, vaultAddr string) vaultAPI.Logical {
	var err error
	var vault vaultAPI.Logical
	var vClient      *vaultAPI.Client

	vaultCFG := *vaultAPI.DefaultConfig()

	vaultCFG.Address = vaultAddr

	vClient, err = vaultAPI.NewClient(&vaultCFG)
	if err != nil {
		log.Panic(err)
	}

	vClient.SetToken(token)

	vault = *vClient.Logical()

	return vault
}


// Recursively delete secrets in targetVault starting at targetKey
func recursiveDelete(targetVault vaultAPI.Logical, targetKey string) {
	result := list(targetVault, targetKey)

	for _, key := range result  {

		fullTargetKey := targetKey + "/" + key
		lastChar := fullTargetKey[len(fullTargetKey)-1:]

		// If the key ends in / we have to recursively copy its keys
		if lastChar == "/" {
			// Remove the trailing slash
			fullTargetKey = fullTargetKey[0:len(fullTargetKey)-1]
			recursiveDelete(targetVault, fullTargetKey)
			continue
		}

		_, err := targetVault.Delete(fullTargetKey)
		if (err != nil) {
			log.Panic(err)
		}
		log.Printf("Deleted key=%v", fullTargetKey)

	}

}
