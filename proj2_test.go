package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/cs161-staff/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
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
		return
	}


	t.Log("No Password Test")
	// We can assume that username isn't empty but what about the password?
	_, pass_err := InitUser("Bob", "")
	if pass_err == nil {
		// t.Error says the test fails
		t.Error("Should not be able to create accounts with no password -> ", pass_err)
		return
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

	username := "Barry"
	for i := 0; i < 10000; i++ {
		username = username + "barry"
	}
	_, long_err := InitUser(username, "fubar")
	if err != nil {
		t.Error("Failed to instantiate user with long username ->", long_err)
	}

	// Alice's user struct should be intact
	same_u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user -> ", err)
	} else if u.Username != same_u.Username {
		t.Error("Alice's user data should be untouched")
	}
}

// Datastore Corruption Tests
func TestUsers4(t *testing.T) {
	clear()
	t.Log("Datastore Corruption Tests")

	// You can set this to false!
	userlib.SetDebugStatus(true)


	// Initiate user alice
	_, err := InitUser("alice", "fubar")
	// Should error as the username alice already exists
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// Get alice's user struct for later use
	u,_ := GetUser("alice", "fubar")


	// Delete alice's user struct from the datastore
	structUUIDHMAC, UUID_err := userlib.HMACEval(make([]byte, 16), []byte("alice" + "struct"))
	if UUID_err != nil {
		t.Error("UUID Error ->", UUID_err)
	}
	userlib.DatastoreDelete(bytesToUUID(structUUIDHMAC))


	// Trying to access Alice's user struct should return an error
	_, deleted_err := GetUser("alice", "fubar")
	if deleted_err == nil {
		t.Error("Should not get user ->", deleted_err)
		return
	}
	t.Log("Successfully returned error when datastore UUID deleted ->", deleted_err)


	// Initiate bob's user struct
	bob, err2 := InitUser("bob", "fubar")
	// Should error as the username alice already exists
	if err2 != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err2)
		return
	}

	// Corrupt bob's user struct
	u.Username = "bob"
	StoreUserStruct(u)
	t.Log("Original Bob's Account: ", bob)
	t.Log("Corrupted Data:", u)

	// Trying to access bob's user struct should return an error
	_, corrupted_err := GetUser("bob", "fubar")
	if corrupted_err == nil {
		t.Error("Should not get user since user sturct is corrupted")
		return
	}
	t.Log("Successfully returned error when datastore got corrupted ->", corrupted_err)
}


func TestStorage(t *testing.T) {
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
}

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
