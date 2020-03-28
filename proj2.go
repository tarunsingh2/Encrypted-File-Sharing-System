package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes: 
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	password string

	PrivateDecKey userlib.PKEDecKey
	PrivateSignKey userlib.DSSignKey

	UUIDMap map[string]uuid.UUID
	OriginalOwnerMap map[string]string
	SharedUsersMap map[string][]string
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing 
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Generate public keys
	encKey, decKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("PKEKeyGen failed!")
	}

	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("DSKeyGen failed!")
	}

	//Store public keys on Keystore
	if err := userlib.KeystoreSet(username + "EncKey", encKey); err != nil {
		return nil, errors.New("Storing encryption key failed!")
	}
	if err := userlib.KeystoreSet(username + "VerifyKey", verifyKey); err != nil {
		return nil, errors.New("Storing verification key failed!")
	}

	//Initialize User struct
	userdata.Username = username
	userdata.password = password
	userdata.PrivateDecKey = decKey
	userdata.PrivateSignKey = signKey
	userdata.UUIDMap = make(map[string]uuid.UUID)
	userdata.OriginalOwnerMap = make(map[string]string)
	userdata.SharedUsersMap = make(map[string][]string)

	//Store User struct on Datastore
	if err := StoreUserStruct(userdataptr); err != nil {
		return nil, err
	}

	//Store password hash on Datastore
	passwordHash := userlib.Argon2Key([]byte(password), []byte(username), 16)
	passwordUUIDHMAC, _ := userlib.HMACEval(make([]byte, 16), []byte(username + "password"))
	userlib.DatastoreSet(bytesToUUID(passwordUUIDHMAC), passwordHash)

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	userdata.password = password

	//Authenticate user
	passwordUUIDHMAC, err := userlib.HMACEval(make([]byte, 16), []byte(username + "password"))
	if err != nil {
		return nil, errors.New("HMAC Failed")
	}
	passwordUUID := bytesToUUID(passwordUUIDHMAC)
	passwordHash, ok := userlib.DatastoreGet(passwordUUID)
	if !ok {
		return nil, errors.New("User not found")
	}

	inputHash := userlib.Argon2Key([]byte(password), []byte(username), 16)
	if !testEq(inputHash, passwordHash) {
		return nil, errors.New("Password incorrect or data corrupted")
	}

	//Generate decryption and HMAC keys for User struct
	structEncKey, structHMACKey, err := GenerateStructKeys(username, password)
	if err != nil {
		return nil, err
	}

	//Retrieve, authenticate, decrypt, and unmarshal User struct
	structUUIDHMAC, err := userlib.HMACEval(make([]byte, 16), []byte(username + "struct"))
	if err != nil {
		return nil, errors.New("HMAC failed!")
	}
	encryptedStruct, ok := userlib.DatastoreGet(bytesToUUID(structUUIDHMAC))
	if !ok {
		return nil, errors.New("User data corrupted")
	}
	marshalledStruct, err := MACThenDecrypt(encryptedStruct, structEncKey, structHMACKey)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(marshalledStruct, userdataptr); err != nil {
		return nil, errors.New("Unmarshalling User struct failed!")
	}

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename 
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	//Fetch stored user struct and update local copy
	storedUser, err := GetUser(userdata.Username, userdata.password)
	if err != nil {
		return
	}
	*userdata = *storedUser

	//Check if filename already exists
	fileHeaderUUID, ok := userdata.UUIDMap[filename]
	if !ok {
		//If no, generate random keys, random UUIDs for header and data
		fileEncKey, fileHMACKey := userlib.RandomBytes(16), userlib.RandomBytes(16)
		fileDataUUID := bytesToUUID(userlib.RandomBytes(16))
		fileHeaderUUID := bytesToUUID(userlib.RandomBytes(16))

		//Store in map
		userdata.UUIDMap[filename] = fileHeaderUUID
		userdata.OriginalOwnerMap[filename] = userdata.Username
		userdata.SharedUsersMap[filename] = make([]string, 0)

		//Store keys on datastore
		userdata.StoreKeys(userdata.Username, fileEncKey, fileHMACKey, fileHeaderUUID)

		//Store encrypted file on datastore
		ciphertext, err := EncryptThenMAC(data, fileEncKey, fileHMACKey)
		if err != nil {
			return
		}
		userlib.DatastoreSet(fileDataUUID, ciphertext)

		//Store encrypted file header on datastore
		ciphertext, err = EncryptThenMAC(fileDataUUID[:], fileEncKey, fileHMACKey)
		if err != nil {
			return
		}
		userlib.DatastoreSet(fileHeaderUUID, ciphertext)

		//Store updated User struct on Datastore
		if err := StoreUserStruct(userdata); err != nil {
			return
		}

	} else {
		//Get keys from datastore
		fileEncKey, fileHMACKey, err := userdata.GetKeys(userdata.OriginalOwnerMap[filename], fileHeaderUUID)
		if err != nil {
			return
		}

		//Make sure this user has not been revoked
		encryptedHeader, ok := userlib.DatastoreGet(fileHeaderUUID)
		if !ok {
			return
		}

		_, err = MACThenDecrypt(encryptedHeader, fileEncKey, fileHMACKey)
		if err != nil {
			return
		}

		//Store encrypted file header on datastore
		fileDataUUID := bytesToUUID(userlib.RandomBytes(16))
		ciphertext, err := EncryptThenMAC(fileDataUUID[:], fileEncKey, fileHMACKey)
		if err != nil {
			return
		}
		userlib.DatastoreSet(fileHeaderUUID, ciphertext)

		//Store encrypted file data on datastore
		ciphertext, err = EncryptThenMAC(data, fileEncKey, fileHMACKey)
		if err != nil {
			return
		}
		userlib.DatastoreSet(fileDataUUID, ciphertext)

	}

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	//Fetch updated user struct and update local copy
	storedUser, err := GetUser(userdata.Username, userdata.password)
	if err != nil {
		return err
	}
	*userdata = *storedUser

	//Make sure file exists
	fileHeaderUUID, ok := userdata.UUIDMap[filename]
	if !ok {
		return errors.New("File not found")
	}

	//Get symmetric file keys from datastore
	fileEncKey, fileHMACKey, err := userdata.GetKeys(userdata.OriginalOwnerMap[filename], fileHeaderUUID)
	if err != nil {
		return err
	}

	//Get header from datastore
	encryptedHeader, ok := userlib.DatastoreGet(fileHeaderUUID)
	if !ok {
		return errors.New("Datastore corrupted, file header not found")
	}

	header, err := MACThenDecrypt(encryptedHeader, fileEncKey, fileHMACKey)
	if err != nil {
		return errors.New("File header corrupted")
	}

	//Encrypt and store data at random UUID
	fileDataUUID := bytesToUUID(userlib.RandomBytes(16))
	ciphertext, err := EncryptThenMAC(data, fileEncKey, fileHMACKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileDataUUID, ciphertext)

	//Add UUID of addition to header
	header = append(header, fileDataUUID[:]...)

	//Reencrypt and store header on datastore
	ciphertext, err = EncryptThenMAC(header, fileEncKey, fileHMACKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileHeaderUUID, ciphertext)

	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	//Fetch stored User struct and update local copy
	storedUser, err := GetUser(userdata.Username, userdata.password)
	if err != nil {
		return nil, err
	}
	*userdata = *storedUser

	//Access file UUID from User struct
	fileUUID, ok := userdata.UUIDMap[filename]
	if !ok {
		return nil, errors.New("File not found")
	}

	//Get file keys from datastore
	fileEncKey, fileHMACKey, err := userdata.GetKeys(userdata.OriginalOwnerMap[filename], fileUUID)
	if err != nil {
		return nil, err
	}

	//Get encrypted file header from Datastore, decrypt/authenticate with keys
	encryptedFile, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return nil, errors.New("Datastore corrupted, file not found")
	}

	header, err := MACThenDecrypt(encryptedFile, fileEncKey, fileHMACKey)
	if err != nil {
		return nil, errors.New("File corrupted")
	}
	if len(header) < 16 {
		return nil, errors.New("File corrupted")
	}

	//Concatenate all pieces of file from header
	var fileData []byte
	for len(header) > 0 {
		address := header[:16]
		encryptedFile, ok = userlib.DatastoreGet(bytesToUUID(address))
		if !ok {
			return nil, errors.New("Datastore corrupted, file not found")
		}
		file, err := MACThenDecrypt(encryptedFile, fileEncKey, fileHMACKey)
		if err != nil {
			return nil, errors.New("File corrupted")
		}
		fileData = append(fileData, file...)
		header = header[16:]
	}

	return fileData, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
	//Fetch stored User struct and update local copy
	storedUser, err := GetUser(userdata.Username, userdata.password)
	if err != nil {
		return "", err
	}
	*userdata = *storedUser

	//Get keys for file from datastore
	fileUUID, ok := userdata.UUIDMap[filename]
	if !ok {
		return "", errors.New("File not found")
	}
	originalOwner, ok := userdata.OriginalOwnerMap[filename]
	if !ok {
		return "", errors.New("File not found")
	}
	fileEncKey, fileHMACKey, err := userdata.GetKeys(originalOwner, fileUUID)
	if err != nil {
		return "", err
	}

	//Encrypt symmetric file keys with recipient's public key and store on datastore
	if err = userdata.StoreKeys(recipient, fileEncKey, fileHMACKey, fileUUID); err != nil {
		return "", err
	}

	//Encrypt and sign UUID + original owner ---> magic_string
	magic_bytes, err := userdata.EncryptThenSign(append(fileUUID[:], []byte(originalOwner)...), recipient)
	if err != nil {
		return "", err
	}
	magic_string = string(magic_bytes)

	//Add recipient to shared users map in User struct
	userdata.SharedUsersMap[filename] = append(userdata.SharedUsersMap[filename], recipient)

	//Store User struct on Datastore
	if err = StoreUserStruct(userdata); err != nil {
		return "", err
	}

	//Store shared user list for file on Datastore
	if err = StoreSharedUsersList(userdata, originalOwner, filename); err != nil {
		return "", err
	}

	return magic_string, nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	//Fetch stored User struct and update local copy
	storedUser, err := GetUser(userdata.Username, userdata.password)
	if err != nil {
		return err
	}
	*userdata = *storedUser

	//Check if user already has a file with this name
	_, ok := userdata.UUIDMap[filename]
	if ok {
		return errors.New("User already has a file with this name")
	}

	//Verify and decrypt magic_string ----> UUID + original owner
	plaintext, err := userdata.VerifyThenDecrypt([]byte(magic_string), sender)
	if err != nil {
		return err
	}
	fileUUID, originalOwner := bytesToUUID(plaintext[:16]), string(plaintext[16:])

	//Get symmetric keys from datastore
	//TODO: Need to allow for case where original owner has overwritten keys before receive is called
	fileEncKey, fileHMACKey, err := userdata.GetKeys(sender, fileUUID)
	if err != nil {
		return err
	}

	//Reupload symmetric keys encrypted for self
	userdata.StoreKeys(userdata.Username, fileEncKey, fileHMACKey, fileUUID)

	//Update User struct maps
	userdata.UUIDMap[filename] = fileUUID
	userdata.OriginalOwnerMap[filename] = originalOwner
	userdata.SharedUsersMap[filename] = make([]string, 0)

	//Store updated user struct on datastore
	if err = StoreUserStruct(userdata); err != nil {
		return err
	}

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {

	//Fetch updated user struct
	storedUser, err := GetUser(userdata.Username, userdata.password)
	if err != nil {
		return err
	}
	*userdata = *storedUser

	//Check if user is original owner
	originalOwner, ok := userdata.OriginalOwnerMap[filename]
	if !ok {
		return errors.New("File not found")
	}
	if originalOwner != userdata.Username {
		return errors.New("This user is not the original owner of the file")
	}

	//Load and decrypt file
	data, err := userdata.LoadFile(filename)

	//Remove target from shared users list
	removedUser := false
	userList := userdata.SharedUsersMap[filename]
	for i, s := range userList {
		if s == target_username {
			userList[i] = userList[len(userList)-1] 
			userList = userList[:len(userList)-1]
			removedUser = true
		}
	}
	if !removedUser {
		return errors.New("Target user does not have access to file")
	}

	//Generate new keys
	fileEncKey, fileHMACKey := userlib.RandomBytes(16), userlib.RandomBytes(16)

	//Store new keys for self on datastore
	if err = userdata.StoreKeys(userdata.Username, fileEncKey, fileHMACKey, userdata.UUIDMap[filename]); err != nil {
		return err
	}

	//Iteratively store new keys for all children on datastore
	fileUUID := userdata.UUIDMap[filename]
	var queue []string
	queue = userdata.SharedUsersMap[filename]
	for len(queue) > 0 {
		if err = userdata.StoreKeys(queue[0], fileEncKey, fileHMACKey, userdata.UUIDMap[filename]); err != nil {
			return err
		}
		uuidHMAC, err := userlib.HMACEval(make([]byte, 16), append([]byte(queue[0] + "UserList"), fileUUID[:]...))
		if err != nil {
			return err
		}
		listUUID := bytesToUUID(uuidHMAC)
		encryptedList, ok := userlib.DatastoreGet(listUUID)
		if ok {
			//return errors.New("User's shared users list corrupted")
			marshalledStruct, err := userdata.VerifyThenDecrypt(encryptedList, queue[0])
			if err != nil {
				return err
			}
			var newUserList []string
			if err = json.Unmarshal(marshalledStruct, &newUserList); err != nil {
				return err
			}
			queue = append(queue, newUserList...)
		}
		queue = queue[1:]
	}

	fileDataUUID := bytesToUUID(userlib.RandomBytes(16))

	//Store encrypted file header on datastore
	ciphertext, err := EncryptThenMAC(fileDataUUID[:], fileEncKey, fileHMACKey)
	if err != nil {
		return
	}
	userlib.DatastoreSet(userdata.UUIDMap[filename], ciphertext)

	//Encrypt file with new keys and store on datastore
	ciphertext, err = EncryptThenMAC(data, fileEncKey, fileHMACKey)
	if err != nil {
		return
	}
	userlib.DatastoreSet(fileDataUUID, ciphertext)

	//Store user struct on datastore
	if err = StoreUserStruct(userdata); err != nil {
		return err
	}

	return
}


func (userdata *User) StoreKeys(recipient string, fileEncKey []byte, fileHMACKey []byte, fileUUID uuid.UUID) (err error) {
	//Generate UUID for key storage
	uuidHMAC, err := userlib.HMACEval(make([]byte, 16), append(fileUUID[:], []byte(recipient)...))
	if err != nil {
		return err
	}
	uuid := bytesToUUID(uuidHMAC)

	//Encrypt then sign keys
	ciphertext, err := userdata.EncryptThenSign(append(fileEncKey, fileHMACKey...), recipient)
	if err != nil {
		return err
	}

	//Store on datastore
	userlib.DatastoreSet(uuid, ciphertext)
	return
}


func (userdata *User) GetKeys(sender string, fileUUID uuid.UUID) (fileEncKey []byte, fileHMACKey []byte, err error) {
	//Generate UUID where keys are stored
	uuidHMAC, err := userlib.HMACEval(make([]byte, 16), append(fileUUID[:], []byte(userdata.Username)...))
	if err != nil {
		return nil, nil, err
	}
	uuid := bytesToUUID(uuidHMAC)

	//Get encrypted keys from datastore
	encryptedKeys, ok := userlib.DatastoreGet(uuid)
	if !ok {
		return nil, nil, errors.New("Keys not found")
	}

	//Verify then decrypt keys (could be signed by either self or sender)
	keys, err := userdata.VerifyThenDecrypt(encryptedKeys, sender)
	if err != nil {
		return nil, nil, err
	}

	return keys[:16], keys[16:], nil
}

func StoreSharedUsersList(userdata *User, originalOwner string, filename string) (err error) {
	//Generate UUID to store list at
	fileUUID, _ := userdata.UUIDMap[filename]
	uuidHMAC, err := userlib.HMACEval(make([]byte, 16), append([]byte(userdata.Username + "UserList"), fileUUID[:]...))
	if err != nil {
		return err
	}
	listUUID := bytesToUUID(uuidHMAC)

	//Marshall, encrypt and sign for original owner
	marshalledList, err := json.Marshal(userdata.SharedUsersMap[filename])
	encryptedList, err := userdata.EncryptThenSign(marshalledList, originalOwner)
	if err != nil {
		return err
	}

	//Store on datastore
	userlib.DatastoreSet(listUUID, encryptedList)
	return nil
}

func StoreUserStruct(userdata *User) (err error) {
	//Generate encryption and HMAC keys for User struct
	structEncKey, structHMACKey, err := GenerateStructKeys(userdata.Username, userdata.password)
	if err != nil {
		return err
	}

	//Marshal, encrypt, HMAC, and store User struct
	marshalledStruct, err := json.Marshal(userdata)
	if err != nil {
		return err
	}
	encryptedStruct, err := EncryptThenMAC(marshalledStruct, structEncKey, structHMACKey)
	if err != nil {
		return err
	}

	structUUIDHMAC, err := userlib.HMACEval(make([]byte, 16), []byte(userdata.Username + "struct"))
	if err != nil {
		return err
	}
	userlib.DatastoreSet(bytesToUUID(structUUIDHMAC), encryptedStruct)

	return nil
}


func (userdata *User) VerifyThenDecrypt(ciphertext []byte, sender string) (plaintext []byte, err error){
	if len(ciphertext) <= 256 {
		return nil, errors.New("Ciphertext corrupted")
	}

	ciphertext, signature := ciphertext[:len(ciphertext)-256], ciphertext[len(ciphertext)-256:]

	selfVerifyKey, _ := userlib.KeystoreGet(userdata.Username + "VerifyKey")
	senderVerifyKey, _ := userlib.KeystoreGet(sender + "VerifyKey")
	if err = userlib.DSVerify(selfVerifyKey, ciphertext, signature); err != nil {
		if err = userlib.DSVerify(senderVerifyKey, ciphertext, signature); err != nil {
			return nil, errors.New("Encrypted data corrupted - Could not verify")
		}
	}
	plaintext, err = userlib.PKEDec(userdata.PrivateDecKey, ciphertext)
	if err != nil {
		return nil, errors.New("Encrypted data corrupted - Could not decrypt")
	}
	return plaintext, nil
}


func (userdata *User) EncryptThenSign(plaintext []byte, recipient string) (ciphertext []byte, err error) {
	//Get recipient's public encryption key
	encKey, ok := userlib.KeystoreGet(recipient + "EncKey")
	if !ok {
		return nil, errors.New("Recipient not found!")
	}

	//Encrypt plaintext with recipient's public key
	ciphertext, err = userlib.PKEEnc(encKey, plaintext)
	if err != nil {
		return nil, err
	}

	//Sign ciphertext with user's private signing key
	signature, err := userlib.DSSign(userdata.PrivateSignKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return append(ciphertext, signature...), nil
}


func EncryptThenMAC(plaintext []byte, encKey []byte, HMACKey []byte) (ciphtertext []byte, err error) {
	ciphertext := userlib.SymEnc(encKey, userlib.RandomBytes(16), plaintext)
	MAC, err := userlib.HMACEval(HMACKey, ciphertext)
	if err != nil {
		return nil, errors.New("HMAC failed!")
	}
	return append(ciphertext, MAC...), nil
}


func MACThenDecrypt(ciphertext []byte, encKey []byte, HMACKey []byte) (plaintext []byte, err error) {
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 64 {
		return nil, errors.New("Ciphertext invalid")
	}
	ciphertext, cipherHMAC := ciphertext[:ciphertextLen-64], ciphertext[ciphertextLen-64:]
	calculatedHMAC, err := userlib.HMACEval(HMACKey, ciphertext)
	if err != nil {
		return nil, errors.New("HMAC failed")
	}
	if !userlib.HMACEqual(calculatedHMAC, cipherHMAC) {
		return nil, errors.New("HMAC did not match")
	}
	plaintext = userlib.SymDec(encKey, ciphertext)
	return plaintext, nil
}


func GenerateStructKeys(username string, password string) (encKey []byte, HMACKey []byte, err error) {
	masterKey := userlib.Argon2Key([]byte(password), []byte(username + "MasterKey"), 16)
	structEncKey, err := userlib.HashKDF(masterKey, []byte("encryption"))
	structEncKey = structEncKey[:16]
	if err != nil {
		return nil, nil, errors.New("HKDF failed!")
	}
	structHMACKey, err := userlib.HashKDF(masterKey, []byte("HMAC"))
	structHMACKey = structHMACKey[:16]
	if err != nil {
		return nil, nil, errors.New("HKDF failed!")
	}
	return structEncKey, structHMACKey, nil	
}


// Returns whether two byte slices are equal
func testEq(a, b []byte) bool {
	if (a == nil) != (b == nil) { 
        return false; 
    }

    if len(a) != len(b) {
        return false
    }

    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}
