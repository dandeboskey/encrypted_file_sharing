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
	//"strings"

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

// InsertNewUser
func (t *Tree) InsertNewUser(sender string, recipient string) {
    var file_tree =*t
    var cur_node = *file_tree.Root
    if cur_node.Left == nil && cur_node.Right == nil && cur_node.Key != sender {
        return
    }
    if cur_node.Key == sender {
        if cur_node.Left != nil {
            new_node := Node{Left: nil, Right: nil, Key: recipient}
            cur_node.Left = &new_node
        } else if cur_node.Right != nil {
            new_node := Node{Left: nil, Right: nil, Key: recipient}
            cur_node.Right = &new_node
        }
        return
    } else {
        LeftTree := Tree{cur_node.Left}
        LeftTree.InsertNewUser(sender, recipient)
        RightTree := Tree{cur_node.Right}
        RightTree.InsertNewUser(sender, recipient)
        return
    }
}

// RemoveUserBranch
func (t *Tree) RemoveUserBranch(user string) {
    var file_tree = *t
    var cur_node = *file_tree.Root
    // cannot remove owner so do not need to check if cur_node == user
    if cur_node.Left == nil && cur_node.Right == nil && cur_node.Key != user { // base case
        return
    }
    var LeftNode = *(cur_node.Left)
    var RightNode = *(cur_node.Right)
    if LeftNode.Key == user {
        cur_node.Left = nil
        return
    } else if RightNode.Key == user {
        cur_node.Right = nil
        return
    }
    LeftTree := Tree{cur_node.Left}
    RightTree := Tree{cur_node.Right}
    LeftTree.RemoveUserBranch(user)
    RightTree.RemoveUserBranch(user)
}

// Add Remaining Users to List
func (t *Tree) AddToList(list *[]string) {
    var file_tree = *t
    var cur_node = *file_tree.Root
    if file_tree.Root == nil {
        return
    }
    *list = append(*list, cur_node.Key)
    LeftTree := Tree{cur_node.Left}
    RightTree := Tree{cur_node.Right}
    LeftTree.AddToList(list)
    RightTree.AddToList(list)
}

// End Source: https://www.golangprograms.com/golang-program-for-implementation-of-linked-list.html

// Type File struct

type File_struct struct {
	Contents  List // a linked list with head and tail nodes (containing prev, next, contents)
	Num_bytes int
	File_tree Tree
}

// Type Invitation struct

type Invitation struct {
	REEncrypt_key		 userlib.PKEEncKey
	Decrypt_file_key_RSA userlib.PKEDecKey // used for decrypting file_struct
	File_UUID            uuid.UUID         // randomized file ID used to obtain file struct from DataStore
	DS_sign_key			 userlib.PrivateKeyType
	Owner                bool              // true if user created the file
	Current				 string
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
	InvitationMap      map[string]uuid.UUID              // hash(filename) -> UUID to obtain invitation struct (for each file) from datastore, will have decryption key for file
	//FileSignMap        map[string]userlib.PrivateKeyType // hash(filename) -> DS sign key (for each file)
	//FileEncryptionMap  map[string]userlib.PKEEncKey      // hash(filename) -> file encryption key (for future re-encryption during appends)
	InviteUUIDs 		map[string][]uuid.UUID
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
	userlib.KeystoreSet(string(userlib.Hash([]byte(username+"_DS"))), DS_verify_key)
	// create all of our maps
	userdata.InvitationMap = make(map[string]uuid.UUID)
	userdata.InviteUUIDs = make(map[string][]uuid.UUID)
	//userdata.FileSignMap = make(map[string]userlib.PrivateKeyType)
	//userdata.FileEncryptionMap = make(map[string]userlib.PKEEncKey)
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
	user_array := make([]interface{}, 2)
	user_array[0] = userdata_ciphertext
	user_array[1] = userdata_signature
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
		var realdummy = make([]interface{}, 2)
		json.Unmarshal(User, &realdummy)
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
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	var numBytes int
	numBytes = len(contentBytes)
	// throw content bytes into linkedlist node
	LLNode := LL_Node{Prev: nil, Next: nil, Contents: contentBytes}
	FileList := List{Head: &LLNode, Tail: &LLNode}
	TreeNode := Node{Key: userdata.Username, Left: nil, Right: nil}
	UserTree := Tree{Root: &TreeNode}
	// put filestruct in datastore
	FileStruct := File_struct{Contents: FileList, Num_bytes: numBytes, File_tree: UserTree}
	// generate two symmetric key pairs
	// first keypair for file encryption
	var Encryption_key_RSA userlib.PKEEncKey
	var Decryption_key_RSA userlib.PKEDecKey
	Encryption_key_RSA, Decryption_key_RSA, err = userlib.PKEKeyGen()
	var file_enc []byte
	file_enc = userlib.Hash([]byte(filename+"_enc"))
	userlib.KeystoreSet(string(file_enc), Encryption_key_RSA)
	// second keypair for file signing
	var DS_signKey userlib.DSSignKey
	var DS_verifyKey userlib.DSVerifyKey
	DS_signKey, DS_verifyKey, err = userlib.DSKeyGen()
	if err != nil {
		return
	}
	userlib.KeystoreSet(string(userlib.Hash([]byte(filename+"_ds"))), DS_verifyKey)
	var file_uuid uuid.UUID
	file_uuid = uuid.New()
	Invite := Invitation{REEncrypt_key: Encryption_key_RSA, DS_sign_key: DS_signKey, Decrypt_file_key_RSA: Decryption_key_RSA, File_UUID: file_uuid, Owner: true, Current: userdata.Username}
	var invite_uuid uuid.UUID
	invite_uuid = uuid.New()
	userdata.InvitationMap[string(file_enc)] = invite_uuid
	userdata.InviteUUIDs[filename] = make([]uuid.UUID, 0)
	userdata.InviteUUIDs[filename] = append(userdata.InviteUUIDs[filename], invite_uuid)
	// Encrypt then MAC the file struct, put into datastore
	var ciphertext_file []byte
	var plaintext_file []byte
	var random_key = userlib.Argon2Key(userlib.RandomBytes(16), userlib.RandomBytes(16), 16)
	plaintext_file, err = json.Marshal(FileStruct)
	if err != nil {
		return
	}
	ciphertext_file = userlib.SymEnc(random_key, userlib.RandomBytes(16), plaintext_file)
	//ciphertext_file, err = userlib.PKEEnc(Encryption_key_RSA, plaintext_enc)
	if err != nil {
		return
	}
	var enc_random_key []byte
	enc_random_key, err = userlib.PKEEnc(Encryption_key_RSA, random_key)
	if err != nil {
		return
	}
	var signature_file []byte
	var signature_random_key []byte
	signature_file, err = userlib.DSSign(DS_signKey, ciphertext_file)
	//signature_random_key, err = userlib.DSSign(DS_signKey, enc_random_key)
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
	var userbytes []byte
	userbytes, err = json.Marshal(userdata.Username)
	if err != nil {
		return
	}
	hash = userlib.Hash(userbytes)
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
	// get array from datastore, verify DS, unencrpt inv -> get invitation
	var file_hash string
	file_hash = string(userlib.Hash([]byte(filename)))
	var val, err = userdata.InvitationMap[file_hash]
	if err != true {
		return nil
	}
	var inv_ciphertext_DS, ok = userlib.DatastoreGet(val)
	if ok != true {
		return nil
	}
	var dummyptr *[]interface{}
	json.Unmarshal(inv_ciphertext_DS, dummyptr)
	var realdummy = *dummyptr
	var inv_DS_key userlib.PublicKeyType

	inv_DS_key, ok = userlib.KeystoreGet(string(userlib.Hash([]byte(userdata.Username + "_DS"))))
	if ok != true {
		return nil
	}
	var verification_ds = realdummy[1].([]byte)
	var ciphertext = realdummy[0].([]byte)
	var err2 error
	err2 = userlib.DSVerify(inv_DS_key, ciphertext, verification_ds)
	if err2 != nil {
		return err2
	}
	var plaintext []byte
	plaintext, err2 = userlib.PKEDec(userdata.Decryption_key_RSA, ciphertext)
	if err2 != nil {
		return err2
	}
	var inv Invitation
	var invptr = &inv
	err2 = json.Unmarshal(plaintext, invptr)
	if err2 != nil {
		return err2
	}

	// check owner is true
	if inv.Owner != true {
		return nil
	}

	// get filestruct from Datastore
	var file_uuid = inv.File_UUID
	var file_dec_key = inv.Decrypt_file_key_RSA
	var encrypted_file_struct, ok2 = userlib.DatastoreGet(file_uuid)
	if ok2 != true {
		return nil
	}
	var file_verify_key, ok3 = userlib.KeystoreGet(string(userlib.Hash([]byte(filename + "_ds"))))
	if ok3 != true {
		return nil
	}
	var dummyptr2 *[]interface{}
	json.Unmarshal(encrypted_file_struct, dummyptr2)
	var realdummy2 = *dummyptr2
	var verification_ds2 = realdummy2[1].([]byte)
	var ciphertext2 = realdummy2[0].([]byte)
	err2 = userlib.DSVerify(file_verify_key, ciphertext2, verification_ds2)
	if err2 != nil {
		return err2
	}
	var plaintext2 []byte
	plaintext2, err2 = userlib.PKEDec(file_dec_key, ciphertext2)
	if err2 != nil {
		return err2
	}
	var file_struct File_struct
	var file_struct_ptr = &file_struct
	json.Unmarshal(plaintext2, file_struct_ptr)

	// get file contents
	// append to contents.tail and update num_bytes
	var file_list = file_struct.Contents
	var tail_ptr = file_list.Tail
	new_node := LL_Node{Prev: tail_ptr, Next: nil, Contents: content}
	*tail_ptr.Next = new_node
	file_list.Tail = &new_node
	file_struct.Num_bytes += len(content)

	// re-encrypt and re-sign and re-store file_struct
	var file_bytes []byte
	var encKey userlib.PKEEncKey
	var sign userlib.PrivateKeyType
	var cipher []byte
	var signature []byte
	file_bytes, err2 = json.Marshal(file_struct)
	if err2 != nil {
		return nil
	}
	encKey = inv.REEncrypt_key
	cipher, err2 = userlib.PKEEnc(encKey, file_bytes)
	if err2 != nil {
		return nil
	}
	
	sign = inv.DS_sign_key
	signature, err2 = userlib.DSSign(sign, cipher)
	if err2 != nil {
		return nil
	}

	array := []interface{}{cipher, signature}
	var arr []byte
	arr, err2 = json.Marshal(array)
	if err2 != nil {
		return nil
	}
	userlib.DatastoreSet(file_uuid, arr)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var ok bool
	var inv_uuid uuid.UUID
	var file_hash []byte
	var inv_contents []byte
	var dummyptr *[]interface{}
	// get the file hash, retrieve contents from datastore
	file_hash = userlib.Hash([]byte(filename))
	inv_uuid = userdata.InvitationMap[string(file_hash)]
	inv_contents, ok = userlib.DatastoreGet(inv_uuid)
	if ok != true {
		return
	}
	json.Unmarshal(inv_contents, dummyptr)
	// unencrypt and verify the invitation
	var realdummy = *dummyptr
	var inv_DS_key userlib.PublicKeyType
	inv_DS_key, ok = userlib.KeystoreGet(string(userlib.Hash([]byte(userdata.Username + "_DS"))))
	if ok != true {
		return
	}
	var verification_ds = realdummy[1].([]byte)
	var ciphertext = realdummy[0].([]byte)
	var err2 error
	err2 = userlib.DSVerify(inv_DS_key, ciphertext, verification_ds)
	if err2 != nil {
		return
	} 
	// decrypt the ciphertext, which should be the invitation
	var plaintext []byte
	plaintext, err2 = userlib.PKEDec(userdata.Decryption_key_RSA, ciphertext)
	if err2 != nil {
		return
	}
	var invite Invitation
	var invptr = &invite
	err2 = json.Unmarshal(plaintext, invptr)
	if err2 != nil {
		return
	}
	// retrieve the file
	var file_uuid = invite.File_UUID
	var file_dec_key = invite.Decrypt_file_key_RSA
	var encrypted_file_struct, ok2 = userlib.DatastoreGet(file_uuid)
	if ok2 != true {
		return
	} 
	// get verification key
	var file_verify_key, ok3 = userlib.KeystoreGet(string(userlib.Hash([]byte(filename + "_ds"))))
	if ok3 != true {
		return
	}
	var dummyptr2 *[]interface{}
	// unmarshal and verify file struct
	json.Unmarshal(encrypted_file_struct, dummyptr2)
	var realdummy2 = *dummyptr2
	var verification_ds2 = realdummy2[1].([]byte)
	var ciphertext2 = realdummy2[0].([]byte)
	err2 = userlib.DSVerify(file_verify_key, ciphertext2, verification_ds2)
	if err2 != nil {
		return
	}
	var plaintext2 []byte
	// unencrypt to get the file struct
	plaintext2, err2 = userlib.PKEDec(file_dec_key, ciphertext2)
	if err2 != nil {
		return
	}
	var file_struct File_struct
	var file_struct_ptr = &file_struct
	json.Unmarshal(plaintext2, file_struct_ptr)
	var file_list = file_struct.Contents
	var head = file_list.Head
	// get all of the contents
	for curr := head; curr != nil; curr = curr.Next {
		content = append(content, curr.Contents...)
	}
	return content, err2
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// verify that the recipient exists
	var hash []byte
	var ok bool
	hash, err = json.Marshal(recipientUsername)
	if err != nil {
		return
	}
	// verify the file exists, and that the user has access
	var file_hash []byte
	file_hash = userlib.Hash([]byte(filename))
	var invite_bytes []byte
	inv_id, ok := userdata.InvitationMap[string(file_hash)]
	if !ok {
		return
	}
	userdata.InviteUUIDs[filename] = append(userdata.InviteUUIDs[filename], inv_id)
	invite_bytes, ok = userlib.DatastoreGet(inv_id)
	if !ok {
		return
	}
	var inv_DS_key userlib.PublicKeyType
	inv_DS_key, ok = userlib.KeystoreGet(string(userlib.Hash([]byte(userdata.Username + "_DS"))))
	if ok != true {
		return
	}
	// user access invitation, verify that the invite is valid
	var dummyptr *[]interface{}
	json.Unmarshal(invite_bytes, dummyptr)
	var realdummy = *dummyptr
	var ciphertext = realdummy[0].([]byte)
	var inv_arr_ds = realdummy[1].([]byte)
	err = userlib.DSVerify(inv_DS_key, ciphertext, inv_arr_ds)
	if err != nil {
		return
	}
	var plaintext []byte
	plaintext, err = userlib.PKEDec(userdata.Decryption_key_RSA, ciphertext)
	if err != nil {
		return
	}
	var inv Invitation
	var invptr = &inv
	err = json.Unmarshal(plaintext, invptr)
	if err != nil {
		return
	}
	// general invite structure
	new_invite := Invitation{REEncrypt_key: inv.REEncrypt_key, DS_sign_key: inv.DS_sign_key, Decrypt_file_key_RSA: inv.Decrypt_file_key_RSA, File_UUID: inv.File_UUID, Owner: false, Current: recipientUsername}
	var invite_uuid uuid.UUID
	invite_uuid = uuid.New()
	userdata.InviteUUIDs[filename] = append(userdata.InviteUUIDs[filename], invite_uuid)
	var recipient_enc_key userlib.PKEEncKey
	recipient_enc_key, ok = userlib.KeystoreGet(string(userlib.Hash(hash)))
	if !ok {
		return
	}
	plaintext, err = json.Marshal(new_invite)
	if err != nil {
		return
	}
	// encrypt with recipient's public key
	ciphertext, err = userlib.PKEEnc(recipient_enc_key, plaintext)
	if err != nil {
		return
	} 
	// sign with user's ds sign key
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
	var userdata_plaintext, err6 = json.Marshal(userdata)
	if err6 != nil {
		return
	}
	// reencrypt and resign user structs after appending to their invitation mapping
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
	// return invitation 
	return invite_uuid, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// use the invitationPtr to retrieve the invitation
	var enc_inv []byte
	var ok bool
	var err error
	enc_inv, ok = userlib.DatastoreGet(invitationPtr)
	if !ok {
		return nil
	}
	// verify and decrypt the invitation
	var dummyptr *[]interface{}
	json.Unmarshal(enc_inv, dummyptr)
	var realdummy = *dummyptr
	var cipher = realdummy[0].([]byte)
	var verification_ds = realdummy[1].([]byte)
	var key userlib.PublicKeyType
	key, ok = userlib.KeystoreGet(senderUsername + "_DS")
	if !ok {
		return nil
	}
	err = userlib.DSVerify(key, cipher, verification_ds)
	if err != nil {
		return nil
	}
	var unenc_inv []byte
	unenc_inv, err = userlib.PKEDec(userdata.Decryption_key_RSA, cipher)
	if err != nil {
		return nil
	}
	var inv Invitation
	var invptr = &inv
	err = json.Unmarshal(unenc_inv, invptr)
	if err != nil {
		return nil
	}
	// update the userdata's mappings invitation map
	userdata.InvitationMap[string(userlib.Hash([]byte(filename)))] = invitationPtr
	// update the file's user tree
	var file_uuid = inv.File_UUID
	var file_dec_key = inv.Decrypt_file_key_RSA
	var encrypted_file_struct []byte
	encrypted_file_struct, ok = userlib.DatastoreGet(file_uuid)
	if ok != true {
		return nil
	}
	var file_verify_key, ok3 = userlib.KeystoreGet(string(userlib.Hash([]byte(filename + "_ds"))))
	if ok3 != true {
		return nil
	}
	var dummyptr2 *[]interface{}
	json.Unmarshal(encrypted_file_struct, dummyptr2)
	var realdummy2 = *dummyptr2
	var verification_ds2 = realdummy2[1].([]byte)
	var ciphertext2 = realdummy2[0].([]byte)
	err = userlib.DSVerify(file_verify_key, ciphertext2, verification_ds2)
	if err != nil {
		return nil
	}
	var plaintext2 []byte
	// unencrypt to get the file struct
	plaintext2, err = userlib.PKEDec(file_dec_key, ciphertext2)
	if err != nil {
		return nil
	}
	var file_struct File_struct
	var file_struct_ptr = &file_struct
	json.Unmarshal(plaintext2, file_struct_ptr)
	var file_tree = file_struct.File_tree

	// modify file_tree
	var u = *userdata
	file_tree.InsertNewUser(senderUsername, u.Username)
	// reencrypt file
	var ciphertext_file []byte
	var plaintext_file []byte
	plaintext_file, err = json.Marshal(file_struct)

	if err != nil {
		return nil
	}
	ciphertext_file, err = userlib.PKEEnc(inv.REEncrypt_key, plaintext_file)
	if err != nil {
		return nil
	}
	var signature_file []byte
	signature_file, err = userlib.DSSign(inv.DS_sign_key, ciphertext_file)
	if err != nil {
		return nil
	}
	array_file := []interface{}{ciphertext_file, signature_file}
	var arr_file []byte
	arr_file, err = json.Marshal(array_file)
	if err != nil {
		return nil
	}
	userlib.DatastoreSet(file_uuid, arr_file)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// get the invitation
	var ok bool
	var inv_uuid uuid.UUID
	var file_hash []byte
	var inv_contents []byte
	var dummyptr *[]interface{}
	// get the file hash, retrieve contents from datastore
	file_hash = userlib.Hash([]byte(filename))
	inv_uuid = userdata.InvitationMap[string(file_hash)]
	inv_contents, ok = userlib.DatastoreGet(inv_uuid)
	if ok != true {
		return nil
	}
	json.Unmarshal(inv_contents, dummyptr)
	// unencrypt and verify the invitation
	var realdummy = *dummyptr
	var inv_DS_key userlib.PublicKeyType
	inv_DS_key, ok = userlib.KeystoreGet(string(userlib.Hash([]byte(userdata.Username + "_DS"))))
	if ok != true {
		return nil
	}
	var verification_ds = realdummy[1].([]byte)
	var ciphertext = realdummy[0].([]byte)
	var err2 error
	err2 = userlib.DSVerify(inv_DS_key, ciphertext, verification_ds)
	if err2 != nil {
		return nil
	} 
	// decrypt the ciphertext, which should be the invitation
	var plaintext []byte
	plaintext, err2 = userlib.PKEDec(userdata.Decryption_key_RSA, ciphertext)
	if err2 != nil {
		return nil
	}
	var invite Invitation
	var invptr = &invite
	err2 = json.Unmarshal(plaintext, invptr)
	if err2 != nil {
		return nil
	} 
	if invite.Owner == false {
		return nil
	}
	// retrieve the file
	var file_uuid = invite.File_UUID
	var file_dec_key = invite.Decrypt_file_key_RSA
	var encrypted_file_struct, ok2 = userlib.DatastoreGet(file_uuid)
	if ok2 != true {
		return nil
	} 
	// get verification key
	var file_verify_key, ok3 = userlib.KeystoreGet(string(userlib.Hash([]byte(filename + "_ds"))))
	if ok3 != true {
		return nil
	}
	var dummyptr2 *[]interface{}
	// unmarshal and verify file struct
	json.Unmarshal(encrypted_file_struct, dummyptr2)
	var realdummy2 = *dummyptr2
	var verification_ds2 = realdummy2[1].([]byte)
	var ciphertext2 = realdummy2[0].([]byte)
	err2 = userlib.DSVerify(file_verify_key, ciphertext2, verification_ds2)
	if err2 != nil {
		return nil
	}
	var plaintext2 []byte
	// unencrypt to get the file struct
	plaintext2, err2 = userlib.PKEDec(file_dec_key, ciphertext2)
	if err2 != nil {
		return nil
	}
	var file_struct File_struct
	var file_struct_ptr = &file_struct
	json.Unmarshal(plaintext2, file_struct_ptr)
	// remove branch from file tree
	file_struct.File_tree.RemoveUserBranch(recipientUsername)

	// go through the remaining tree, update the invitation private keys
	var list[]string
	file_struct.File_tree.AddToList(&list)
	// create the new file
	FileStruct := File_struct{Contents: file_struct.Contents, Num_bytes: file_struct.Num_bytes, File_tree: file_struct.File_tree}
	// generate keys encryption/decryption (invitations)
	var err error
	var Encryption_key_RSA userlib.PKEEncKey
	var Decryption_key_RSA userlib.PKEDecKey
	Encryption_key_RSA, Decryption_key_RSA, err = userlib.PKEKeyGen()
	var file_enc []byte
	file_enc = userlib.Hash([]byte(filename+"_enc"))
	userlib.KeystoreSet(string(file_enc), Encryption_key_RSA)
	// generate keys digital signatures (invitations)
	var DS_signKey userlib.DSSignKey
	var DS_verifyKey userlib.DSVerifyKey
	DS_signKey, DS_verifyKey, err = userlib.DSKeyGen()
	var newfileuuid = uuid.New()
	if err != nil {
		return nil
	}
	userlib.KeystoreSet(string(userlib.Hash([]byte(filename+"_ds"))), DS_verifyKey)
	var id_list = userdata.InviteUUIDs[filename]

	var ciphertext_file []byte
	var plaintext_file []byte
	plaintext_file, err = json.Marshal(FileStruct)
	if err != nil {
		return nil
	}
	ciphertext_file, err = userlib.PKEEnc(invite.REEncrypt_key, plaintext_file)
	if err != nil {
		return nil
	}
	var signature_file []byte
	signature_file, err = userlib.DSSign(invite.DS_sign_key, ciphertext_file)
	if err != nil {
		return nil
	}
	array_file := []interface{}{ciphertext_file, signature_file}
	var arr_file []byte
	arr_file, err = json.Marshal(array_file)
	if err != nil {
		return nil
	}
	userlib.DatastoreSet(file_uuid, arr_file)
	// new encryption
	for _, username := range list {
		for _, inv_id := range id_list {
			inv_contents, ok = userlib.DatastoreGet(inv_id)
			if ok != true {
				return nil
			}
			json.Unmarshal(inv_contents, dummyptr)
			// unencrypt and verify the invitation
			var realdummy = *dummyptr
			var inv_DS_key userlib.PublicKeyType
			inv_DS_key, ok = userlib.KeystoreGet(string(userlib.Hash([]byte(userdata.Username + "_DS"))))
			if ok != true {
				return nil
			}
			var verification_ds = realdummy[1].([]byte)
			var ciphertext = realdummy[0].([]byte)
			var err2 error
			err2 = userlib.DSVerify(inv_DS_key, ciphertext, verification_ds)
			if err2 != nil {
				return nil
			} 
			// decrypt the ciphertext, which should be the invitation
			var plaintext []byte
			plaintext, err2 = userlib.PKEDec(userdata.Decryption_key_RSA, ciphertext)
			if err2 != nil {
				return nil
			}
			var invite Invitation
			var invptr = &invite
			err2 = json.Unmarshal(plaintext, invptr)
			if err2 != nil {
				return nil
			} 
			if invite.Current == username {
				invite.DS_sign_key = DS_signKey
				invite.Decrypt_file_key_RSA = Decryption_key_RSA
				invite.File_UUID = newfileuuid
				invite.REEncrypt_key = Encryption_key_RSA
				plaintext, err = json.Marshal(invite)
				if err != nil {
					return nil
				}
				// encrypt with recipient's public key
				var hash, err = json.Marshal(username)
				if err != nil {
					return nil
				}
				var rec_key_enc, ok = userlib.KeystoreGet(string(userlib.Hash(hash)))
				if !ok {
					return nil
				}
				ciphertext, err = userlib.PKEEnc(rec_key_enc, plaintext)
				if err != nil {
					return nil
				} 
				// sign with user's ds sign key
				var signature []byte
				hash, err = json.Marshal(username+"_DS")
				if err != nil {
					return nil
				}
				signature, err = userlib.DSSign(userdata.DS_sign_key, ciphertext)
				if err != nil {
					return nil
				} 
				array := []interface{}{ciphertext, signature}
				var arr []byte
				arr, err = json.Marshal(array)
				if err != nil {
					return nil
				} 
				userlib.DatastoreSet(inv_id, arr)
			} else {
				continue
			}
		}
	}

	return nil
}
