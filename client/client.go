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
	Prev     *LL_Node
	Next     *LL_Node
	Contents []byte
}

type List struct {
	Head *LL_Node
	Tail *LL_Node
}

func (L *List) Insert(Contents []byte) {
	list := &LL_Node{
		Next:     L.Head,
		Contents: Contents,
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
	Contents      List
	Num_bytes     int
	contents_UUID uuid.UUID
}

// Type File struct

type File_struct struct {
	Contents  List // a linked list with head and tail nodes (containing prev, next, contents)
	Num_bytes int
	File_tree Tree
}

// Type Invitation struct

type Invitation struct {
	Decrypt_file_key_RSA userlib.PKEDecKey // used for decrypting file_struct
	File_UUID            uuid.UUID         // randomized file ID used to obtain file struct from DataStore
	owner                bool              // true if user created the file
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username           string                            // username
	Root_key           []byte                            // a deterministic symmetric key used to derive user.UUID, and decrypt/encrypt the user struct,
	User_UUID          uuid.UUID                         // user's UUID, derived from root_key
	Decryption_key_RSA userlib.PKEDecKey                 // a random asymmetric key used for decrypting invitations directed towards the user, the corresponding encryption key is in keystore to encrypt invitations.
	DS_sign_key        userlib.PrivateKeyType            // used to sign user struct, the corresponding verification key is placed in KeyStore. sender signs with their key, receiver checks that senders key matches public
	InvitationMap      map[[]byte]uuid.UUID              // hash(filename) -> UUID to obtain invitation struct (for each file) from datastore, will have decryption key for file
	SignMap            map[[]byte]userlib.PrivateKeyType // hash(filename) -> MAC verification key (for each file)
	FileEncryptionMap  map[[]byte]userlib.PKEEncKey      // hash(filename) -> file encryption key (for future re-encryption during appends)
	FileSignMap        map[[]byte]userlib.PrivateKeyType // hash(filename) -> file ds sign key
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
	var err4 error
	if err4 != nil {
		return
	}
	Encryption_key_RSA, userdata.Decryption_key_RSA, err4 = userlib.PKEKeyGen()
	var hash []byte
	hash, err = json.Marshal(userdata.Username)
	if err != nil {
		return
	}
	userlib.KeystoreSet(string(userlib.Hash(hash)), Encryption_key_RSA)
	var err5 error
	var DS_verify_key userlib.PublicKeyType
	userdata.DS_sign_key, DS_verify_key, err5 = userlib.DSKeyGen()
	if err5 != nil {
		return
	}
	// put digital signature key in keystore
	userlib.KeystoreSet(username+"_DS", DS_verify_key)
	// create all of our maps
	userdata.InvitationMap = make(map[[]byte]Invitation)
	userdata.SignMap = make(map[[]byte]userlib.PrivateKeyType)
	userdata.FileEncryptionMap = make(map[[]byte]userlib.PKEEncKey)
	// get plaintext in bytes
	var userdata_plaintext, err6 = json.Marshal(userdata)
	if err6 != nil {
		return
	}
	// encrypt plaintext, get ciphertext
	var userdata_ciphertext = userlib.SymEnc(userdata.Root_key, userlib.RandomBytes((16)), userdata_plaintext)
	// sign the ciphertext
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
	var Root_key = userlib.Argon2Key(password_bytes, salt_bytes, 16)
	var err3 error
	var User_UUID uuid.UUID
	User_UUID, err3 = uuid.FromBytes(Root_key)
	var User, ok = userlib.DatastoreGet(User_UUID)
	if err3 != nil {
		return
	}
	if ok == true {
		var dummyptr *[]interface{}
		json.Unmarshal(User, dummyptr)
		var realdummy = *dummyptr
		var key, ok = userlib.KeystoreGet(username + "_DS")
		if ok == true {
			var verification_ds = realdummy[1].([]byte)
			var cipher = realdummy[0].([]byte)
			var err4 error
			err4 = userlib.DSVerify(key, cipher, verification_ds)
			if err4 != nil {
				return
			}
			// everything is verified
			var plaintext = userlib.SymDec(Root_key, cipher)
			var err5 error
			err5 = json.Unmarshal(plaintext, userdataptr)
			if err5 != nil {
				return
			}
			return userdataptr, err5
		} else {
			return
		}
	}

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// deterministic
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	var numBytes int
	numBytes = len(contentBytes)
	// throw content bytes into linkedlist node
	userlib.DatastoreSet(storageKey, contentBytes)
	LLNode := LL_Node{Prev: nil, Next: nil, Contents: contentBytes}
	FileList := List{Head: &LLNode, Tail: &LLNode}
	var content_uuid uuid.UUID
	content_uuid = uuid.New()
	FileContents := File_contents{Contents: FileList, Num_bytes: numBytes, contents_UUID: content_uuid}
	TreeNode := Node{Key: userdata.Username, Left: nil, Right: nil}
	UserTree := Tree{Root: &TreeNode}
	var filestruct_uuid uuid.UUID
	filestruct_uuid = uuid.New()
	// put filestruct in datastore
	FileStruct := File_struct{File_contents: FileContents, File_tree: UserTree, File_UUID: filestruct_uuid}
	// generate two symmetric key pairs
	// first keypair for file appends
	var Encryption_key_RSA userlib.PKEEncKey
	var Decryption_key_RSA userlib.PKEDecKey
	Encryption_key_RSA, Decryption_key_RSA, err = userlib.PKEKeyGen()
	var file_hash []byte
	file_hash = userlib.Hash([]byte(filename))
	userdata.FileEncryptionMap[string(file_hash)] = Encryption_key_RSA
	if err != nil {
		return
	}
	// store the next pair of keys in datastore
	var DS_signKey userlib.DSSignKey
	var DS_verifyKey userlib.DSVerifyKey
	DS_signKey, DS_verifyKey, err = userlib.DSKeyGen()
	if err != nil {
		return
	}
	userlib.KeystoreSet(string(userlib.Hash([]byte(filename+"_ds"))), DS_verifyKey)
	userdata.SignMap[string(file_hash)] = DS_signKey
	var file_uuid uuid.UUID
	file_uuid = uuid.New()
	Invite := Invitation{Decrypt_file_key_RSA: Decryption_key_RSA, File_UUID: file_uuid, owner: true}
	var invite_uuid uuid.UUID
	invite_uuid = uuid.New()
	userdata.InvitationMap[string(file_hash)] = invite_uuid
	// Encrypt then MAC the file struct, put into datastore
	var ciphertext_file []byte
	var plaintext_file []byte

	plaintext_file, err = json.Marshal(FileStruct)
	if err != nil {
		return
	}
	ciphertext_file, err = userlib.PKEEnc(Encryption_key_RSA, plaintext_file)
	if err != nil {
		return
	}
	var signature_file []byte
	signature_file, err = userlib.DSSign(DS_signKey, ciphertext_file)
	if err != nil {
		return
	}
	array_file := []interface{}{ciphertext_file, signature_file}
	var arr_file []byte
	arr_file, err = json.Marshal(array_file)
	if err != nil {
		return
	}
	userlib.DatastoreSet(file_uuid, arr_file)
	// Encrypt then MAC the invite
	var encKey userlib.PKEEncKey
	var ok bool
	var hash []byte
	hash, err = json.Marshal(userdata.Username)
	if err != nil {
		return
	}
	encKey, ok = userlib.KeystoreGet(string(hash))
	if !ok {
		return
	}
	var ciphertext []byte
	var plaintext []byte
	plaintext, err = json.Marshal(Invite)
	if err != nil {
		return
	}
	ciphertext, err = userlib.PKEEnc(encKey, plaintext)
	if err != nil {
		return
	}
	var signature []byte
	signature, err = userlib.DSSign(userdata.DS_sign_key, ciphertext)
	if err != nil {
		return
	}
	array := []interface{}{ciphertext, signature}
	var arr []byte
	arr, err = json.Marshal(array)
	if err != nil {
		return
	}
	userlib.DatastoreSet(invite_uuid, arr)
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
