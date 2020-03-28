package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/cs161-staff/userlib"
	_"encoding/json"
	_ "encoding/hex"
	_"github.com/google/uuid"
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
		if len(value) < 50 {
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
		if len(value) < 50 {
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
// func TestFileAppend(t *testing.T) {
// 	clear()
// 	t.Log("Test if file append works correctly")
// 	u, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}
//
//
// }

func TestShare(t *testing.T) {
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
