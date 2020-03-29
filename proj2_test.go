package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/cs161-staff/userlib"
	_"encoding/json"
	_ "encoding/hex"
	"github.com/google/uuid"
	"strings"
	_ "errors"
	_ "strconv"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

// [USER TESTS] Testing the instantiation and get of users
// Simple initialization test
func TestUsers1(t *testing.T) {
	clear()
	// You can set this to false!
	userlib.SetDebugStatus(true)

	t.Log("Simple Init and Get Test")

	// Creating user alice
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Instantiated user ->", u.Username)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.


	// Should return alice correctly
	get_u, err := GetUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to get user", err)
		return
	}
	t.Log("Got user -> ", get_u.Username)


	// Wrong password should not return user
	_, wrongpass_err := GetUser("alice", "wrongpass")
	if wrongpass_err == nil {
		t.Error("Wrong password should not allow access to user")
		return
	}
	t.Log("Wrong password did not return user info ->", wrongpass_err)


	t.Log("No Username Test")
	// We can assume that username isn't empty but what about the password?
	_, user_err := InitUser("", "x")
	if user_err == nil {
		// t.Error says the test fails
		t.Error("Should not be able to create accounts with no username -> ", user_err)
	}


	t.Log("No Password Test")
	// We can assume that username isn't empty but what about the password?
	_, pass_err := InitUser("Bob", "")
	if pass_err == nil {
		// t.Error says the test fails
		t.Error("Should not be able to create accounts with no password -> ", pass_err)
	}
}

// Username duplication test. Should return an error on the second initialization
func TestUsers2(t *testing.T) {
	clear()
	t.Log("Duplicate Initialization")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	u, err := InitUser("alice", "fubar")
	// Should error as the username alice already exists
	if err != nil {
		t.Log("Should return an error when trying to create an account with an existing username->", err)
	} else {
		t.Error("Created a new user when it wasn't supposed to", u)
	}
}

// Trying to create an account with a very long username
func TestUsers3(t *testing.T) {
	clear()
	t.Log("Long Username Initalization")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	// Should error as the username alice already exists
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	username := strings.Repeat("barry", 100000)
	_, long_err := InitUser(username, "fubar")
	if err != nil {
		t.Error("Failed to instantiate user with long username ->", long_err)
	}

	// Alice's user struct should be intact
	same_u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user -> ", err)
	} else if !reflect.DeepEqual(u, same_u) {
		t.Error("Alice's user data should be untouched")
	}
}

// Datastore User Struct Corruption Tests
func TestUsers4(t *testing.T) {
	clear()
	t.Log("Datastore Corruption Tests")

	// You can set this to false!
	userlib.SetDebugStatus(true)


	// Initiate user alice
	_, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}


	// Delete alice's user struct from the datastore
	data_store := userlib.DatastoreGetMap()
	var value_alice []byte
	for key, value := range data_store {
		value_alice = value
    	userlib.DatastoreDelete(key)
	}


	// Trying to access Alice's user struct should return an error
	_, deleted_err := GetUser("alice", "fubar")
	if deleted_err == nil {
		t.Error("Should not get user ->", deleted_err)
		return
	}
	t.Log("Successfully returned error when datastore UUID deleted ->", deleted_err)


	// Initiate bob's user struct
	_, err2 := InitUser("bob", "fubar")
	// Should error as the username alice already exists
	if err2 != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err2)
		return
	}

	for key, _ := range data_store {
    	data_store[key] = value_alice
	}
	_, corrupted_err := GetUser("bob", "fubar")
	if deleted_err == nil {
		t.Error("Should not get user ->", corrupted_err)
		return
	}
	t.Log("Successfully returned error when bob's user struct was corrupted ->", corrupted_err)


	for key, _ := range data_store {
    	data_store[key] = nil
	}
	_, data_del_err := GetUser("bob", "fubar")
	if data_del_err == nil {
		t.Error("Should not get user ->", corrupted_err)
		return
	}
	t.Log("Successfully returned error when bob's user struct was deleted but not the UUID ->", data_del_err)
}


// [FILE STORAGE AND LOADING TESTS]
// Simple store and load test
func TestStorage1(t *testing.T) {
	clear()
	t.Log("Simple storing and loading test")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

// Test if storing twice with the same name overwrites files
func TestStorage2(t *testing.T) {
	clear()
	t.Log("Test if store twice overwrites files")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	store_v1 := []byte("This is a test")
	u.StoreFile("file1", store_v1)

	load_v1, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}

	store_v2 := []byte("This is not a test")
	u.StoreFile("file1", store_v2)

	load_v2, err3 := u.LoadFile("file1")
	if err3 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}

	if reflect.DeepEqual(load_v1, load_v2) {
		t.Error("File with same name did not overwrite", load_v1, load_v2)
		return
	}
}

// Tests old version of a file
func TestFakeFile(t *testing.T) {
	clear()
	old_map := make(map[uuid.UUID][]byte)
	t.Log("Test if alice loads a file added by an attacker")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	store_v1 := []byte("This is a test")
	u.StoreFile("file1", store_v1)

	data_store := userlib.DatastoreGetMap()
	for key, value := range data_store {
		if 20 < len(value) && len(value) < 200 {
			old_map[key] = value
		}
	}

	store_v2 := []byte("This is not a test")
	u.StoreFile("file1", store_v2)

	for key, value := range old_map {
		data_store[key] = value
	}

	_, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Load failed", err2)
		return
	}
}

// Tests if bob can access alice's files
func TestAccess(t *testing.T) {
	clear()
	t.Log("File access tests")
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	bob, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	alice.StoreFile("file1", v)

	_, err2 := bob.LoadFile("file1")
	if err2 == nil {
		t.Error("Bob should not be able to access alice's files", err2)
		return
	}
}

// Tests if bob can access alice's files when switched
func TestBadAccess(t *testing.T) {
	clear()
	saved_map := make(map[uuid.UUID][]byte)
	var saved_user uuid.UUID
	data_store := userlib.DatastoreGetMap()
	t.Log("File access tests corrupted")
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	// Getting Alice's user key
	for key, value := range data_store {
		if len(value) > 20 {
			saved_user = key
		}
	}

	v := []byte("This is a test")
	alice.StoreFile("file1", v)

	for key, value := range data_store {
		saved_map[key] = value
	}

	bob, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	for key, value := range data_store {
		if len(saved_map[key]) == 0 && len(value) > 20 {
			data_store[key] = data_store[saved_user]
		}
	}

	_, err2 := bob.LoadFile("file1")
	if err2 == nil {
		t.Error("Bob should not be able to access alice's files", err2)
		return
	}
}

// Test for files that have filename of length zero
func TestZeroLength(t *testing.T) {
	clear()
	t.Log("Files with no name test")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	store_v1 := []byte("This file has no name")
	u.StoreFile("", store_v1)

	load_v1, err2 := u.LoadFile("")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}

	if !reflect.DeepEqual(store_v1, load_v1) {
		t.Error("File with no name did not store/load correctly ->", err2)
		return
	}

	store_v2 := []byte("This file also has no name")
	u.StoreFile("", store_v2)

	load_v2, err3 := u.LoadFile("")
	if err3 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}

	if reflect.DeepEqual(load_v1, load_v2) {
		t.Error("Files with no name did not overwrite", load_v1, load_v2)
		return
	}
}

// Test for files that don't exist
func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

// Test file datastore corruption
func TestFile(t *testing.T) {
	clear()
	t.Log("Test if load catches datastore corruption")
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	store_v1 := []byte("This is a test")
	u.StoreFile("file1", store_v1)

	data_store := userlib.DatastoreGetMap()

	// Corrupting files
	for key, value := range data_store {
		if len(value) < 200 {
			data_store[key] = make([]byte, 14)
		}
	}

	_, err1 := u.LoadFile("file1")
	if err1 == nil {
		t.Error("File corrupted and should not load", err1)
		return
	}
	t.Log("Successfully errored with corrupted file ->", err1)


	// File deleted
	store_v2 := []byte("Deleted")
	u.StoreFile("file2", store_v2)

	for key, value := range data_store {
		if len(value) < 200 {
			userlib.DatastoreDelete(key)
		}
	}

	_, err2 := u.LoadFile("file2")
	if err2 == nil {
		t.Error("File corrupted and should not load", err2)
		return
	}
	t.Log("Successfully errored with deleted file ->", err2)
}

// Test the confidentiality of files
func TestFileConfidentiality(t *testing.T) {
	clear()
	t.Log("Basic tests to see if information about files has leaked")

	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	store_f1 := []byte("This is a test")
	u.StoreFile("file1", store_f1)

	data_store := userlib.DatastoreGetMap()
	for key, file := range data_store {
		if reflect.DeepEqual(key, "file1") || reflect.DeepEqual(store_f1, file) {
			t.Error("Information about a file has leaked")
		}
		if len(key) == 5 {
			t.Error("Information about a filename has leaked")
		}
	}
}

// Test file appending
func TestFileAppend(t *testing.T) {
	clear()
	data_store := userlib.DatastoreGetMap()
	t.Log("Test if file append works correctly")

	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	store_f1 := []byte("This is a test ")
	u.StoreFile("file1", store_f1)
	store_f2 := []byte("or is it?")
	u.AppendFile("file1", store_f2)

	load_file, err1 := u.LoadFile("file1")
	if err1 != nil {
		t.Error("File could not load ->", err1)
		return
	}
	if !reflect.DeepEqual(load_file, []byte("This is a test or is it?")) {
		t.Error("File did not append correctly")
	}

	// Corrupting the file to append to
	for key, value := range data_store {
		if len(value) < 200 {
			data_store[key] = userlib.RandomBytes(16)
		}
	}
	store_f3 := []byte("File is corrupted")
	append_error1 := u.AppendFile("file1", store_f3)
	if append_error1 != nil {
		t.Log("Correctly did not append to corrupted file ->", append_error1)
	}

	// Deleting the file to append to
	for key, value := range data_store {
		if len(value) < 200 {
			userlib.DatastoreDelete(key)
		}
	}
	store_f4 := []byte("Should not append")
	append_error2 := u.AppendFile("file1", store_f4)
	if append_error2 != nil {
		t.Log("Correctly could not append to deleted file ->", append_error2)
	}
}

func TestShare1(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}

func TestShare2(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	_, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	data_store := userlib.DatastoreGetMap()
	for key, value := range data_store {
		if len(value) < 200 {
			data_store[key] = userlib.RandomBytes(16)
		}
	}

	_, err3 := u.ShareFile("file1", "bob")
	if err3 == nil {
		t.Error("Corrupted file should not be shared ->", err3)
		return
	}

	v2 := []byte("This is a test")
	u.StoreFile("file2", v2)
	for key, value := range data_store {
		if len(value) < 150 {
			userlib.DatastoreDelete(key)
		}
	}
	_, err4 := u.ShareFile("file2", "bob")
	if err4 == nil {
		t.Error("Deleted file should not be shared")
		return
	}
}

// Corrupted load testing
func TestShare3(t *testing.T) {
	var magic_string string
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	_, err3 := u.ShareFile("file1", "bob")
	if err3 != nil {
		t.Error("Could not share ->", err3)
		return
	}

	data_store := userlib.DatastoreGetMap()
	for key, value := range data_store {
		if len(value) < 200 {
			data_store[key] = userlib.RandomBytes(16)
		}
	}

	err4 := u2.ReceiveFile("file1", "alice", magic_string)
	if err4 == nil {
		t.Error("Should not be able to receive corrupted file")
		return
	}
}

func TestShare4(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	vNew := []byte("This is an updated test")
	u.StoreFile("file1", vNew)

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}
	if !reflect.DeepEqual(v, vNew) {
		t.Error("Shared file is not the same", v, vNew)
		return
	}

	v, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file from bob", err)
		return
	}
	if !reflect.DeepEqual(v, vNew) {
		t.Error("Shared file is not the same", v, vNew)
		return
	}

	vNew = []byte("This is an updated test three")
	u2.StoreFile("file2", vNew)

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}
	if !reflect.DeepEqual(v, vNew) {
		t.Error("Shared file is not the same", v, vNew)
		return
	}

	v, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file from bob", err)
		return
	}
	if !reflect.DeepEqual(v, vNew) {
		t.Error("Shared file is not the same", v, vNew)
		return
	}

}

func TestRevoke(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	v2, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after revoking alice", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after revoking alice", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	// aliceEnc, aliceHMAC, err := u.GetKeys("alice", u.UUIDMap["file1"])
	// t.Log(aliceEnc)
	// t.Log(aliceHMAC)

	// bobEnc, bobHMAC, err := u2.GetKeys("alice", u2.UUIDMap["file2"])
	// t.Log(bobEnc)
	// t.Log(bobHMAC)

	if err = u.RevokeFile("file1", "bob"); err != nil {
		t.Error("Failed to revoke file", err)
	}

	// aliceEnc, aliceHMAC, err = u.GetKeys("alice", u.UUIDMap["file1"])
	// t.Log(aliceEnc)
	// t.Log(aliceHMAC)

	// bobEnc, bobHMAC, err = u2.GetKeys("alice", u2.UUIDMap["file2"])
	// t.Log(bobEnc)
	// t.Log(bobHMAC)

	v2, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after revoking alice", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	u.StoreFile("file1", []byte("This has been updated after Bob was revoked"))

	_, err = u2.LoadFile("file2")
	if err != nil {
		t.Log("Failed to download the file after revoking bob", err)
	} else {
		t.Error("Bob was able to load file after being revoked")
		return
	}
}

func TestAppend(t *testing.T) {
	clear()

	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}

	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}

	if err = u.AppendFile("file1", []byte(" of the append function")); err != nil {
		t.Error("Failed to append to file", err)
	}

	v3, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file after appending", err)
		return
	}

	if !reflect.DeepEqual(v3, append(v, []byte(" of the append function")...)) {
		t.Error("Downloaded file is not the same after appending", v3)
		return
	}

	userlib.DebugMsg(string(v3))

}

func TestShareManyUsers(t *testing.T) {
	clear()

	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	bob, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	data := []byte("This is a test")
	alice.StoreFile("file1", data)

	magic_string, err := alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share file", err)
		return
	}

	if err = bob.ReceiveFile("file2", "alice", magic_string); err != nil {
		t.Error("Failed to receive file", err)
		return
	}

	for i := 0; i < 100; i++ {
		user, err := InitUser(string(i), "fubar")
		if err != nil {
			t.Error("Failed to initialize user", err)
			return
		}
		magic_string, err = bob.ShareFile("file2", string(i))
		if err != nil {
			t.Error("Failed to share file", err)
			return
		}
		if err = user.ReceiveFile("file1", "bob", magic_string); err != nil {
			t.Error("Failed to receive file", err)
			return
		}
	}

}

func TestShareRevokeSequence(t *testing.T) {
	clear()

	//Initialize all users
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	bob, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	charlie, err := InitUser("charlie", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	darren, err := InitUser("darren", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	eddie, err := InitUser("eddie", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
	}

	//Alice stores the file
	data := []byte("This is a test")
	alice.StoreFile("file1", data)

	//Alice shares the file with bob and charlie
	magic_string_bob, err := alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file with bob", err)
		return
	}
	magic_string_charlie, err := alice.ShareFile("file1", "charlie")
	if err != nil {
		t.Error("Failed to share the file with charlie", err)
		return
	}

	//Bob receives the file
	err = bob.ReceiveFile("file2", "alice", magic_string_bob)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	//Bob loads the file
	file_bob, err := bob.LoadFile("file2")
	if err != nil {
		t.Error("Failed to load file by Bob", err)
		return
	}
	if !reflect.DeepEqual(data, file_bob) {
		t.Error("Downloaded file is not the same as the original")
		return
	}

	//Bob updates the file
	data = []byte("This is a test updated by Bob")
	bob.StoreFile("file2", data)

	//Charlie receives the file
	err = charlie.ReceiveFile("file3", "alice", magic_string_charlie)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	//Charlie loads the file
	file_charlie, err := charlie.LoadFile("file3")
	if err != nil {
		t.Error("Failed to load file by Charlie", err)
		return
	}
	if !reflect.DeepEqual(data, file_charlie) {
		t.Error("Downloaded file is not the same as the original")
		return
	}
	t.Log(string(file_charlie))

	//Charlie shares the file with Darren
	magic_string_darren, err := charlie.ShareFile("file3", "darren")
	if err != nil {
		t.Error("Failed to share the file with darren", err)
		return
	}

	//Charlie appends to the file
	if err = charlie.AppendFile("file3", []byte(" and appended to by Charlie")); err != nil {
		t.Error("Charlie failed to append to file", err)
		return
	}

	data = []byte("This is a test updated by Bob and appended to by Charlie")

	//Alice and Bob load latest version of file
	file_alice, err := alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file by Alice", err)
		return
	}
	if !reflect.DeepEqual(data, file_alice) {
		t.Error("Downloaded file is not the same as the original")
		return
	}
	t.Log(string(file_alice))

	file_bob, err = bob.LoadFile("file2")
	if err != nil {
		t.Error("Failed to load file by Bob", err)
		return
	}
	if !reflect.DeepEqual(data, file_bob) {
		t.Error("Downloaded file is not the same as the original")
		return
	}
	t.Log(string(file_bob))

	// //Darren receives the file
	// err = darren.ReceiveFile("file4", "charlie", magic_string_darren)
	// if err != nil {
	// 	t.Error("Failed to receive the share message", err)
	// 	return
	// }

	// aliceEnc, aliceHMAC, err := alice.GetKeys("alice", alice.UUIDMap["file1"])
	// t.Log(aliceEnc)
	// t.Log(aliceHMAC)

	// bobEnc, bobHMAC, err := bob.GetKeys("alice", bob.UUIDMap["file2"])
	// t.Log(bobEnc)
	// t.Log(bobHMAC)

	//Alice revokes Bob's access to the file
	if err = alice.RevokeFile("file1", "bob"); err != nil {
		t.Error("Failed to revoke Bob's access by Alice", err)
		return
	}

	// aliceEnc, aliceHMAC, err = alice.GetKeys("alice", alice.UUIDMap["file1"])
	// t.Log(aliceEnc)
	// t.Log(aliceHMAC)

	// bobEnc, bobHMAC, err = bob.GetKeys("alice", bob.UUIDMap["file2"])
	// t.Log(bobEnc)
	// t.Log(bobHMAC)

	//Darren receives the file
	err = darren.ReceiveFile("file4", "charlie", magic_string_darren)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	//Alice, Charlie, and Darren access the file
	file_alice, err = alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file by Alice", err)
		return
	}
	if !reflect.DeepEqual(data, file_alice) {
		t.Error("Downloaded file is not the same as the original")
		return
	}
	t.Log(string(file_alice))

	file_charlie, err = charlie.LoadFile("file3")
	if err != nil {
		t.Error("Failed to load file by Charlie", err)
		return
	}
	if !reflect.DeepEqual(data, file_charlie) {
		t.Error("Downloaded file is not the same as the original")
		return
	}
	t.Log(string(file_charlie))

	file_darren, err := darren.LoadFile("file4")
	if err != nil {
		t.Error("Failed to load file by Darren", err)
		return
	}
	if !reflect.DeepEqual(data, file_darren) {
		t.Error("Downloaded file is not the same as the original")
		return
	}
	t.Log(string(file_darren))

	//Bob tries to access the file (should fail)
	file_bob, err = bob.LoadFile("file2")
	if err == nil {
		t.Error("Bob was able to load file", err)
		return
	} else {
		t.Log("Bob was not able to load file: ", err)
	}

	//Bob tries to overwrite the file (should fail)
	bad_data := []byte("This file was overwritten after Bob was revoked")
	bob.StoreFile("file2", bad_data)

	//Bob tries to append to file (should fail)
	if err = bob.AppendFile("file2", []byte(" overwriting after revocation")); err == nil {
		t.Error("Successfully appended to file", err)
	} else {
		t.Log("Failed to append to file: ", err)
	}

	//Bob tries to share file (should fail)
	_, err = bob.ShareFile("file2", "eddie")
	if err == nil {
		t.Error("Successfully shared file with eddie")
		return
	} else {
		t.Log("Correctly errored when trying to share file after being revoked: ", err)
	}
	_ = eddie

	//Alice loads the file again (should not be overwritten)
	file_alice, err = alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file by Alice", err)
		return
	}
	if !reflect.DeepEqual(data, file_alice) {
		t.Error("Downloaded file is not the same as the original")
		return
	}
	t.Log(string(file_alice))

	//Alice revokes Charlie
	if err = alice.RevokeFile("file1", "charlie"); err != nil {
		t.Error("Failed to revoke Charlies's access by Alice", err)
		return
	}

	//Charlie tries to access the file (should fail)
	file_charlie, err = charlie.LoadFile("file3")
	if err == nil {
		t.Error("Charlie was able to load file", err)
		return
	} else {
		t.Log("Charlie was not able to load file: ", err)
	}

	//Charlie tries to overwrite the file (should fail)
	bad_data = []byte("This file was overwritten after Charlie was revoked")
	charlie.StoreFile("file3", bad_data)

	//Charie tries to append to file (should fail)
	if err = charlie.AppendFile("file3", []byte(" overwriting after revocation")); err == nil {
		t.Error("Successfully appended to file", err)
	} else {
		t.Log("Failed to append to file: ", err)
	}

	//Charlie tries to share file (should fail)
	_, err = charlie.ShareFile("file3", "eddie")
	if err == nil {
		t.Error("Successfully shared file with eddie")
		return
	} else {
		t.Log("Correctly errored when trying to share file after being revoked: ", err)
	}	

	//Darren tries to access the file (should fail)
	file_darren, err = darren.LoadFile("file4")
	if err == nil {
		t.Error("Darren was able to load file", err)
		return
	} else {
		t.Log("Darren was not able to load file: ", err)
	}

	//Darren tries to overwrite the file (should fail)
	bad_data = []byte("This file was overwritten after Darren was revoked")
	darren.StoreFile("file4", bad_data)

	//Darren tries to append to file (should fail)
	if err = darren.AppendFile("file4", []byte(" overwriting after revocation")); err == nil {
		t.Error("Successfully appended to file", err)
	} else {
		t.Log("Failed to append to file: ", err)
	}

	//Darren tries to share file (should fail)
	_, err = darren.ShareFile("file4", "eddie")
	if err == nil {
		t.Error("Successfully shared file with eddie")
		return
	} else {
		t.Log("Correctly errored when trying to share file after being revoked: ", err)
	}

	//Alice loads the file again (should not be overwritten)
	file_alice, err = alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file by Alice", err)
		return
	}
	if !reflect.DeepEqual(data, file_alice) {
		t.Error("Downloaded file is not the same as the original")
		return
	}
	t.Log(string(file_alice))

	//Alice shares the file with Charlie again
	magic_string, err := alice.ShareFile("file1", "charlie")
	if err != nil {
		t.Error("Failed to share file again with charlie: ", err)
		return
	} 
	if err = charlie.ReceiveFile("file3New", "alice", magic_string); err != nil {
		t.Error("Failed to receive file after being revoked: ", err)
		return
	}

	//Charlie should again have access to the file
	file_charlie, err = charlie.LoadFile("file3New")
	if err != nil {
		t.Error("Failed to load file by Charlie", err)
		return
	}
	if !reflect.DeepEqual(data, file_charlie) {
		t.Error("Downloaded file is not the same as the original")
		return
	}
	t.Log(string(file_charlie))

	//Darren should not have access

	//Darren tries to access the file (should fail)
	file_darren, err = darren.LoadFile("file4")
	if err == nil {
		t.Error("Darren was able to load file", err)
		return
	} else {
		t.Log("Darren was not able to load file: ", err)
	}

	//Darren tries to overwrite the file (should fail)
	bad_data = []byte("This file was overwritten after Darren was revoked")
	darren.StoreFile("file4", bad_data)

	//Darren tries to append to file (should fail)
	if err = darren.AppendFile("file4", []byte(" overwriting after revocation")); err == nil {
		t.Error("Successfully appended to file", err)
	} else {
		t.Log("Failed to append to file: ", err)
	}

	//Darren tries to share file (should fail)
	_, err = darren.ShareFile("file4", "eddie")
	if err == nil {
		t.Error("Successfully shared file with eddie")
		return
	} else {
		t.Log("Correctly errored when trying to share file after being revoked: ", err)
	}

	//Alice should be able to see Charlie's changes
	new_data := []byte("This file is from after Charlie was given access to the file again")
	charlie.StoreFile("file3New", new_data)

	file_alice, err = alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file by Alice", err)
		return
	}
	if !reflect.DeepEqual(new_data, file_alice) {
		t.Error("Downloaded file is not the same as the original")
		return
	}
	t.Log(string(file_alice))

	//Charlie should be able to see Alice's changes
	if err = alice.AppendFile("file1", []byte(" and appended to by Alice")); err != nil {
		t.Error("Failed to append to file: ", err)
		return
	}
	file_charlie, err = charlie.LoadFile("file3New")
	if err != nil {
		t.Error("Failed to load file by Charlie", err)
		return
	}
	if !reflect.DeepEqual(append(new_data, []byte(" and appended to by Alice")...), file_charlie) {
		t.Error("Downloaded file is not the same as the original")
		return
	}
	t.Log(string(file_charlie))

}

func TestInvalidBehavior(t *testing.T) {
	clear()
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Initializing user failed: ", err)
		return
	}
	bob, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Initializing user failed: ", err)
		return
	}
	darren, err := InitUser("darren", "fubar")
	if err != nil {
		t.Error("Initializing user failed: ", err)
		return
	}
	eddie, err := InitUser("eddie", "fubar")
	if err != nil {
		t.Error("Initializing user failed: ", err)
		return
	}

	alice.StoreFile("file1", []byte("This is Alice's test file"))
	bob.StoreFile("file2", []byte("This is Bob's test file"))
	darren.StoreFile("file3", []byte("This is Darren's test file"))

	//GetUser
	_, err = GetUser("charlie", "fubar")
	if err == nil {
		t.Error("Got user that wasn't initialized")
		return
	} else {
		t.Log("Correctly errored on getting uninitialized user: ", err)
	}
	_, err = GetUser("alice", "foobar")
	if err == nil {
		t.Error("Got user with wrong password")
		return
	} else {
		t.Log("Correctly errored on getting user with wrong password: ", err)
	}

	//AppendFile
	if err = alice.AppendFile("this file does not exist", []byte("test data")); err == nil {
		t.Error("Appended to file that doesn't exist")
		return
	} else {
		t.Log("Correctly errored on appending to invalid file: ", err)
	}

	//ShareFile
	_, err = alice.ShareFile("this file does not exist", "bob")
	if err == nil {
		t.Error("Shared file that doesn't exist")
		return
	} else {
		t.Log("Correctly errored on sharing file that does not exist: ", err)
	}

	_, err = alice.ShareFile("file1", "charlie")
	if err == nil {
		t.Error("Shared file with user that doesn't exist")
		return
	} else {
		t.Log("Correctly errored on sharing file with user that doesn't exist: ", err)
	}

	magic_string_alice, err := alice.ShareFile("file1", "darren")
	if err != nil {
		t.Error("Failed to share file with Darren: ", err)
		return
	}

	magic_string_bob, err := bob.ShareFile("file2", "darren")
	if err != nil {
		t.Error("Failed to share file with Darren: ", err)
		return
	}

	if err = darren.ReceiveFile("fileShared", "bob", magic_string_alice); err == nil {
		t.Error("Access token was not from sender")
		return
	} else {
		t.Log("Correctly errored when receiving access token not from sender: ", err)
	}

	if err = darren.ReceiveFile("fileShared", "bob", magic_string_bob); err != nil {
		t.Error("Failed to receive file: ", err)
		return
	}

	if err = darren.ReceiveFile("fileShared", "alice", magic_string_alice); err == nil {
		t.Error("Incorrectly received file with same name")
		return
	} else {
		t.Log("Correctly errored when receiving file with existing name: ", err)
	}

	//RevokeFile
	if err = alice.RevokeFile("file1", "eddie"); err == nil {
		t.Error("Revoked file from user that does not have access")
		return
	} else {
		t.Log("Correctly errored when trying to revoke user that does not have access: ", err)
	}

	magic_string_darren, err := darren.ShareFile("fileShared", "eddie")
	if err != nil {
		t.Error("Failed to share file with Eddie: ", err)
		return
	}

	if err = eddie.ReceiveFile("fileSharedEddie", "darren", magic_string_darren); err != nil {
		t.Error("Failed to receive file: ", err)
		return
	}

	if err = alice.RevokeFile("file1", "eddie"); err == nil {
		t.Error("Revoked file from user who is not a direct child")
		return
	} else {
		t.Log("Correctly errored when trying to revoke user who is not a direct child: ", err)
	}

}

func TestFilenameLengthLeak(t *testing.T) {
	userlib.SetDebugStatus(true)

	clear()
	alice, _ := InitUser("alice", "fubar")
	alice.StoreFile("a", []byte("This is a test"))
	datastore := userlib.DatastoreGetMap()
	sum := 0
	for _, value := range datastore {
		sum = sum + len(value)
	}
	shortLen := sum

	clear()
	alice, _ = InitUser("alice", "fubar")
	alice.StoreFile(strings.Repeat("a", 10000), []byte("This is a test"))
	datastore = userlib.DatastoreGetMap()
	sum = 0
	for _, value := range datastore {
		sum = sum + len(value)
	}
	longLen := sum

	t.Logf("Short len: %d, Long len: %d", shortLen, longLen)
	if shortLen != longLen {
		t.Error("Filename length has been leaked to datastore!")
		return
	}
}

func TestSharingLongUsername(t *testing.T) {
	clear()

	alice, err := InitUser(strings.Repeat("a", 1000), "fubar")
	if err != nil {
		t.Error("Failed to initialize user: ", err)
		return
	}
	bob, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user: ", err)
		return
	}

	data := []byte("This is a test")
	alice.StoreFile("file1", data)

	magic_string, err := alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share file: ", err)
		return
	}

	if err = bob.ReceiveFile("file2", "alice", magic_string); err != nil {
		t.Error("Failed to receive file: ", err)
		return
	}
}
