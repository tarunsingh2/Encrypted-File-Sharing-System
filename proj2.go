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

	PrivateDecKey userlib.PKEDecKey
	PrivateSignKey userlib.DSSignKey

	EncKeysMap map[string][]byte
	HMACKeysMap map[string][]byte
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
	userdata.PrivateDecKey = decKey
	userdata.PrivateSignKey = signKey
	userdata.EncKeysMap = make(map[string][]byte)
	userdata.HMACKeysMap = make(map[string][]byte)
	userdata.UUIDMap = make(map[string]uuid.UUID)
	userdata.OriginalOwnerMap = make(map[string]string)
	userdata.SharedUsersMap = make(map[string][]string)

	//Generate encryption and HMAC keys for User struct
	structEncKey, structHMACKey, err := GenerateStructKeys(username, password)
	if err != nil {
		return nil, err
	}

	//Marshal, encrypt, HMAC, and store User struct
	marshalledStruct, _ := json.Marshal(userdata)
	encryptedStruct := userlib.SymEnc(structEncKey, userlib.RandomBytes(16), marshalledStruct)
	structHMAC, _ := userlib.HMACEval(structHMACKey, encryptedStruct)

	structUUIDHMAC, _ := userlib.HMACEval(make([]byte, 16), []byte(username + "struct"))
	userlib.DatastoreSet(bytesToUUID(structUUIDHMAC), append(encryptedStruct, structHMAC...))

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
	marshalledStruct, err := MACthenDecrypt(encryptedStruct, structEncKey, structHMACKey)
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

	//TODO: This is a toy implementation.
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	packaged_data, _ := json.Marshal(data)
	userlib.DatastoreSet(UUID, packaged_data)
	//End of toy implementation

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	//TODO: This is a toy implementation.
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	packaged_data, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(packaged_data, &data)
	return data, nil
	//End of toy implementation

	return
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

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}


func MACthenDecrypt(ciphertext []byte, encKey []byte, HMACKey []byte) (plaintext []byte, err error) {
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
