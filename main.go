package main

import (
	"log"
	vaultAPI "github.com/hashicorp/vault/api"
	"flag"
)




func main() {

	var sourceVaultAddr, sourceToken, sourceRoot, targetVaultAddr, targetToken, targetRoot string
	var deleteOnly bool
	flag.StringVar(&sourceVaultAddr, "sourceVaultAddr", "", "vault_addr for the copy-from vault, like https://example.com:8200")
	flag.StringVar(&sourceToken, "sourceToken", "", "Token for sourceVaultAddr - best to have read privs only")
	flag.StringVar(&sourceRoot, "sourceRoot", "/secret/", "Root in source tree to start copying from")
	flag.StringVar(&targetVaultAddr, "targetVaultAddr", "", "vault_addr for the copy-to vault, like https://example2.com:8200")
	flag.StringVar(&targetToken, "targetToken", "", "Token for targetVaultAddr - must have write privs")
	flag.StringVar(&targetRoot, "targetRoot", "/secret/copy2", "Root in target tree to start copying to")
	flag.BoolVar(&deleteOnly, "deleteOnly", false, "Set to non-nil to delete from targetRoot on targetVaultAddr")
	flag.Parse()


	if deleteOnly != false {
		if targetVaultAddr == "" || targetRoot == "" {
			log.Fatal("-targetVaultAddr and -targetRoot must be set in order to delete from target")
		}
		log.Printf("Deleting from %s:%s", targetVaultAddr, targetRoot)
	} else {
		if sourceVaultAddr == "" || sourceRoot == "" || targetVaultAddr == "" || targetRoot == "" {
			log.Fatal("both vault and root must be set in order to copy")
		}

		log.Printf("Copying from %s:%s to %s:%s", sourceVaultAddr, sourceRoot, targetVaultAddr, targetRoot)
	}
	sourceVault := getVault(sourceToken, sourceVaultAddr)
	targetVault := getVault(targetToken, targetVaultAddr)

	if (deleteOnly) {
		recursiveDelete(targetVault, targetRoot);
		return
	}
	recursiveCopy(sourceVault, sourceRoot, targetVault, targetRoot)
}


func recursiveCopy(sourceVault vaultAPI.Logical, sourceKey string, targetVault vaultAPI.Logical, targetKey string) {

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
			recursiveCopy(sourceVault, fullSourceKey, targetVault, fullTargetKey)
			continue
		}

		value, err := sourceVault.Read(fullSourceKey)
		if (err != nil) {
			log.Panic(err)
		}

		data := value.Data


		_, err = targetVault.Write(fullTargetKey, data)
		if (err != nil) {
			log.Panic(err)
		}
		// Might not be *value*
		// stringval := data["value"].(string)
		//log.Printf("stringval of data is %v", stringval);
		log.Printf("Wrote key from source=%v to target=%v (value=%v)", fullSourceKey, fullTargetKey, data)

	}
}


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
