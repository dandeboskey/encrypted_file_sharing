package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// Source: https://www.bogotobogo.com/GoLang/GoLang_Binary_Search_Tree.php
type Tree struct {
	Root *Node
}
type Node struct {
	Key   string
	Left  *Node
	Right *Node
}

// Tree
func (t *Tree) insert(data string) {
	if t.Root == nil {
		t.Root = &Node{Key: data}
	} else {
		t.Root.insert(data)
	}
}

// Node
func (n *Node) insert(data string) {
	if data <= n.Key {
		if n.Left == nil {
			n.Left = &Node{Key: data}
		} else {
			n.Left.insert(data)
		}
	} else {
		if n.Right == nil {
			n.Right = &Node{Key: data}
		} else {
			n.Right.insert(data)
		}
	}
}

// End Source: https://www.bogotobogo.com/GoLang/GoLang_Binary_Search_Tree.php

// Source: https://www.golangprograms.com/golang-program-for-implementation-of-linked-list.html

type LL_Node struct {
	Prev *LL_Node
	Next *LL_Node
	Key  []byte
}

type List struct {
	Head *LL_Node
	Tail *LL_Node
}

func (L *List) Insert(Key []byte) {
	list := &LL_Node{
		Next: L.Head,
		Key:  Key,
	}
	if L.Head != nil {
		L.Head.Prev = list
	}
	L.Head = list

	l := L.Head
	for l.Next != nil {
		l = l.Next
	}
	L.Tail = l
}

// End Source: https://www.golangprograms.com/golang-program-for-implementation-of-linked-list.html

// Type File contents struct

type File_contents struct {
	Contents  List
	Num_bytes int
}

// Type File struct

type File_struct struct {
	File_contents File_contents
	File_tree     Tree
}

// Type Invitation struct

type Invitation struct {
	Decrypt_file_key_RSA userlib.PKEDecKey
	File_UUID            uuid.UUID
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username           string                       // username
	Root_key           []byte                       // symmetric key used to encrpt and decrypt user struct
	User_UUID          uuid.UUID                    // user's UUID
	Decryption_key_RSA userlib.PKEDecKey            // used for decrypting invitations directing towards the user
	DS_sign_key        userlib.PrivateKeyType       // used to sign user struct
	InvitationMap      map[string]Invitation        // hash(filename) -> invitation struct
	DecryptionMap      map[string]userlib.PKEDecKey // hash(filename) -> file decryption key
	VerificationMap    map[string][]byte            // hash(filename) -> MAC verification key
}

// You can add other attributes here if you want! But note that in order for attributes to
// be included when this struct is serialized to/from JSON, they must be capitalized.
// On the flipside, if you have an attribute that you want to be able to access from
// this struct's methods, but you DON'T want that value to be included in the serialized value
// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
// begins with a lowercase letter).

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username
	var password_bytes, err1 = json.Marshal(password)
	var salt_bytes, err2 = json.Marshal(1) // salt = 1 for determinism
	if err1 != nil || err2 != nil {
		return
	}
	userdata.Root_key = userlib.Argon2Key(password_bytes, salt_bytes, 16)
	var err3 error
	userdata.User_UUID, err3 = uuid.FromBytes(userdata.Root_key)
	if err3 != nil {
		return
	}
	var Encryption_key_RSA userlib.PKEEncKey
	userlib.KeystoreSet(userdata.Username, Encryption_key_RSA)
	var err4 error
	if err4 != nil {
		return
	}
	Encryption_key_RSA, userdata.Decryption_key_RSA, err4 = userlib.PKEKeyGen()
	var err5 error
	var DS_verify_key userlib.PublicKeyType
	userdata.DS_sign_key, DS_verify_key, err5 = userlib.DSKeyGen()
	if err5 != nil {
		return
	}
	userlib.KeystoreSet(username+"_DS", DS_verify_key)

	userdata.InvitationMap = make(map[string]Invitation)
	userdata.DecryptionMap = make(map[string]userlib.PKEDecKey)
	userdata.VerificationMap = make(map[string][]byte)

	var userdata_plaintext, err6 = json.Marshal(userdata)
	if err6 != nil {
		return
	}
	var userdata_ciphertext = userlib.SymEnc(userdata.Root_key, userlib.RandomBytes((16)), userdata_plaintext)
	var userdata_signature, err7 = userlib.DSSign(userdata.DS_sign_key, userdata_ciphertext)
	if err7 != nil {
		return
	}
	user_array := []interface{}{userdata_ciphertext, userdata_signature}
	var user_array_store, err8 = json.Marshal(user_array)
	if err8 != nil {
		return
	}
	userlib.DatastoreSet(userdata.User_UUID, user_array_store)
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	var password_bytes, err1 = json.Marshal(password)
	var salt_bytes, err2 = json.Marshal(1)
	if err1 != nil || err2 != nil {
		return
	}
	var Root_key = userlib.Argon2Key(password_bytes, salt_bytes, 32)
	var err3 error
	var User_UUID uuid.UUID
	User_UUID, err3 = uuid.FromBytes(Root_key)
	var User, ok = userlib.DatastoreGet(User_UUID)
	if err3 != nil {
		return
	}
	if ok == true {
		var dummyptr *[]interface{}
		var dummy = json.Unmarshal(User, dummyptr)
		var realdummy = *dummyptr
		var err4 error
		var salt []byte
		salt, err4 = json.Marshal(2)
		if err4 != nil {
			return
		}
		var key = userlib.Argon2Key(password_bytes, salt, 16)
		var Verification_MAC, err5 = userlib.HMACEval(key, realdummy[0])
		if err5 != nil {
			return
		}
		if !HMACEqual(Verification_MAC, dummy[1]) {
			return
		}
		SymDec(Root_key, dummy[0])
	}

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
