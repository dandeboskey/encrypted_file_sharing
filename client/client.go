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

// InsertNewUser
func (t *Tree) InsertNewUser(sender string, recipient string) {
	var file_tree = *t
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

func (t *Tree) GetKeys() []string {
	return collectKeys(t.Root, []string{})
}

func collectKeys(node *Node, keys []string) []string {
	if node == nil {
		return keys
	}

	keys = append(keys, node.Key)

	if node.Left != nil {
		keys = collectKeys(node.Left, keys)
	}
	if node.Right != nil {
		keys = collectKeys(node.Right, keys)
	}

	return keys
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
	File_uuid uuid.UUID// a random file ID used to load the file struct from DataStore
	Dec_file_key userlib.PKEDecKey // an RSA private key used to decrypt the File struct
	Verify_file_key userlib.PublicKeyType // a DS verification key used to verify the File struct
	User string // the recipient of the invitation
	Filetree_uuid uuid.UUID // a random ID used to load the file tree from DataStore
	Sym_filetree_key []byte //a random symmetric key used to encrypt and decrypt the file tree
	Sign_filetree_key userlib.PrivateKeyType // a DS signing key used to sign the file tree
	Verify_filetree_key userlib.PublicKeyType // a DS verification key used to verify the file tree
	Owner bool // to check permissions for appending and revocation
	Accepted bool // used in file sharing
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username           string                 // username
	Root_key           []byte                 // a deterministic symmetric key used to derive user.UUID, and decrypt/encrypt the user struct,
	User_UUID          uuid.UUID              // user's UUID, derived from root_key
	Dec_inv_key 	   userlib.PKEDecKey  // an RSA private key used to decrypt invitation structs sent to the user
	Sign_inv_key 	   userlib.PrivateKeyType  // a DS key used to sign invitations structs sent to other others
	InvitationMap 	   map[string]uuid.UUID // maps the filename to the file’s invitation struct’s uuid (random) so that the user may load the invitation struct 
	FileEncMap 		   map[string]userlib.PKEEncKey // maps the filename to the file’s encryption key (File_enc_key)
	FileSignMap        map[string]userlib.PrivateKeyType // maps the filename to the file’s signing key (File_sign_key)
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
	var password_bytes, salt_bytes []byte
	password_bytes, err = json.Marshal(password)
	if err != nil {
		return
	}
	salt_bytes, err = json.Marshal(1) // salt = 1 for determinism
	if err != nil {
		return 
	}
	// generate root key
	userdata.Root_key = userlib.Argon2Key(password_bytes, salt_bytes, 16)
	// generate uuid from rootkey
	userdata.User_UUID, err = uuid.FromBytes(userdata.Root_key)
	if err != nil {
		return
	}
	// generate DS key pairs for sign & verify user struct
	var DS_verify_key userlib.PublicKeyType
	var DS_sign_key userlib.DSSignKey
	DS_sign_key, DS_verify_key, err = userlib.DSKeyGen()
	if err != nil {
		return
	}
	// put verification key in keystore: hash(username + “_user_verify”):Verify_user_key
	userlib.KeystoreSet(string(userlib.Hash([]byte(username+"_user_verify"))), DS_verify_key)
	// generate RSA key pair for encrypting and decrypting invitations
	var Enc_inv_key userlib.PKEEncKey
	Enc_inv_key, userdata.Dec_inv_key, err = userlib.PKEKeyGen()
	// put invitation encryption key in keystore: hash(username + “_inv_enc”):Enc_inv_key
	userlib.KeystoreSet(string(userlib.Hash([]byte(username+"_inv_enc"))), Enc_inv_key)
	// generate DS key pairs for sign & verify invitations
	var inv_verify_key userlib.DSVerifyKey
	userdata.Sign_inv_key, inv_verify_key, err = userlib.DSKeyGen()
	if err != nil {
		return
	}
	// put invitation verification key in keystore: hash(username + “_inv_verify”):Verify_inv_key
	userlib.KeystoreSet(string(userlib.Hash([]byte(username+"_inv_verify"))), inv_verify_key)

	userdata.InvitationMap = make(map[string]uuid.UUID)
	userdata.FileSignMap = make(map[string]userlib.PrivateKeyType)
	userdata.FileEncMap = make(map[string]userlib.PKEEncKey)
	// symmetric encryption then signing
	userdata_bytes, err := json.Marshal(userdata)
	if err != nil {
		return
	}
	var userdata_cipher = userlib.SymEnc(userdata.Root_key, userlib.RandomBytes(16), userdata_bytes)
	userdata_signature, err := userlib.DSSign(DS_sign_key, userdata_cipher)
	if err != nil {
		return
	} 
	user_array := make([]interface{}, 2)
	user_array[0] = userdata_cipher
	user_array[1] = userdata_signature
	user_array_store, err := json.Marshal(user_array)
	if err != nil {
		return
	}
	userlib.DatastoreSet(userdata.User_UUID, user_array_store)
	return &userdata, nil
}

func HybridEncryptThenSign(enc_key userlib.PKEEncKey, sign_key userlib.DSSignKey, data []byte, id uuid.UUID) (err error) {
	// Generate a symmetric key
	var password, salt_bytes, key []byte
	password = userlib.RandomBytes(16)
	salt_bytes = userlib.RandomBytes(16)
	key = userlib.Argon2Key(password, salt_bytes, 16)
	// Encrypt the data with the symmetric key
	ciphertext := userlib.SymEnc(key, userlib.RandomBytes(16), data)
	// Sign the encrypted data
	signed, err := userlib.DSSign(sign_key, ciphertext)
	if err != nil {
		return nil
	}
	// Encrypt the symmetric key
	enc_sym_key, err := userlib.PKEEnc(enc_key, key)
	if err != nil {
		return nil
	}
	// Create an array with (encrypted data, signature, encrypted symmetric key)
	user_array := make([]interface{}, 3)
	user_array[0] = ciphertext
	user_array[1] = signed
	user_array[2] = enc_sym_key
	// Marshal the array
	user_array_store, err := json.Marshal(user_array)
	if err != nil {
		return nil
	}
	// Store array in datastore with id
	userlib.DatastoreSet(id, user_array_store)
}

func HybridVerifyThenDecrypt(dec_key userlib.PKEDecKey, verify_key userlib.DSVerifyKey, data []byte, id uuid.UUID) (content []byte, err error) {
	// Load the data from datastore with id
	enc_data, ok := userlib.DatastoreGet(id)
	if !ok {
		return
	}
	// Unmarshal the array
	realdummy := make([]interface{}, 3)
	json.Unmarshal(enc_data, &realdummy)
	ciphertext := realdummy[0].([]byte)
	verification := realdummy[1].([]byte)
	encrypted_sym_key := realdummy[2].([]byte)
	// Verify the signature with verify_key
	err = userlib.DSVerify(verify_key, ciphertext, verification)
	if err != nil {
		return
	}
	// Decrypt symmetric key (in array) with dec_key
	sym_key, err := userlib.PKEDec(dec_key, encrypted_sym_key)
	if err != nil {
		return
	}
	err = userlib.DSVerify(verify_key, ciphertext, verification)
	if err != nil {
		return
	}
	// Decrypt the encrypted data with the decrypted symmetric key
	new_data := userlib.SymDec(sym_key, ciphertext)
	return new_data, err
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// generate root key for user
	var password_bytes, salt_bytes []byte
	password_bytes, err = json.Marshal(password)
	if err != nil {
		return
	}
	salt_bytes, err = json.Marshal(1) // salt = 1 for determinism
	if err != nil {
		return 
	}
	// generate root key
	root_key := userlib.Argon2Key(password_bytes, salt_bytes, 16)
	// get the user uuid
	user_id, err := uuid.FromBytes(root_key)
	if err != nil {
		return
	} 
	User, ok := userlib.DatastoreGet(user_id)
	// verify that user exists in datastore
	if !ok {
		return
	}
	// pull encrypted & signed user struct from datastore 
	var realdummy = make([]interface{}, 2)
	json.Unmarshal(User, &realdummy)
	key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(username+"_user_verify"))))
	if !ok {
		return
	}
	// verify and decrypt user struct
	var verification_ds = realdummy[1].([]byte)
	var cipher = realdummy[0].([]byte)
	err = userlib.DSVerify(key, cipher, verification_ds)
	if err != nil {
		return
	}
	var plaintext = userlib.SymDec(root_key, cipher)
	// set userdataptr to the unencrypted and verified user struct
	err = json.Unmarshal(plaintext, userdataptr)
	if err != nil {
		return
	}
	return userdataptr, err
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// generate random file uuid
	file_id := uuid.New()
	// generate random invite uuid
	inv_id := uuid.New()
	// InvitationMap := filename:Inv_uuid
	userdata.InvitationMap[filename]=inv_id
	// generate RSA keypair
	Encryption_key_RSA, Decryption_key_RSA, err := userlib.PKEKeyGen()
	// place the encryption key in the user’s FileEncMap 
	userdata.FileEncMap[filename]=Encryption_key_RSA
	// place the decryption key (Dec_file_key) in the file’s Invitation.

	// generate a pair of file digital signature keys
	DS_signKey, DS_verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return
	}
	// place the sign key in FileSignMap 
	userdata.FileSignMap[filename] = DS_signKey
	// place the verification key (Verify_file_key) in the file’s Invitation. 

	// create file struct
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
	// We create a filetree with the user as root.
	UserTree := Tree{Root: &TreeNode}
	UserTree_uuid := uuid.New()
	// create symmetric key for file tree (put in invitation)
	var password, salt_bytes, sym_key []byte
	password = userlib.RandomBytes(16)
	salt_bytes = userlib.RandomBytes(16)
	sym_key = userlib.Argon2Key(password, salt_bytes, 16)
	// create DS key pair for file tree (put both in invitation)
	DS_signKey_ft, DS_verifyKey_ft, err := userlib.DSKeyGen()
	if err != nil {
		return
	}
	// put filestruct in datastore
	FileStruct := File_struct{Contents: FileList, 
		Num_bytes: numBytes, 
		File_tree: UserTree}
	// create invitation struct for owner
	Invite := Invitation{File_uuid: file_id, 
		Dec_file_key: Decryption_key_RSA, 
		Verify_file_key: DS_verifyKey, 
		User: userdata.Username, 
		Filetree_uuid: UserTree_uuid, 
		Sym_filetree_key: sym_key, 
		Sign_filetree_key: DS_signKey_ft, 
		Verify_filetree_key: DS_verifyKey_ft,
		Owner: true,
		Accepted: true}
	// hybrid encrypt then sign file struct
	// store it in DataStore with key = File_uuid
	FileBytes, err := json.Marshal(FileStruct)
	if err != nil {
		return
	}
	err = HybridEncryptThenSign(Encryption_key_RSA, DS_signKey, FileBytes, file_id)
	if err != nil {
		return
	}
	// hybrid encrypt then sign invitation
	// store it in Datastore with key = Inv_uuid
	InviteBytes, err := json.Marshal(Invite)
	if err != nil {
		return
	}
	err = HybridEncryptThenSign(Encryption_key_RSA, DS_signKey, InviteBytes, inv_id)
	if err != nil {
		return
	}
	// symmetric encrypt and sign the filetree
	FileTreeBytes, err := json.Marshal(UserTree)
	if err != nil {
		return
	}
	cipher := userlib.SymEnc(sym_key, userlib.RandomBytes(16), FileTreeBytes)
	// store it in datastore with key = Filetree_uuid
	userlib.DatastoreSet(UserTree_uuid, cipher)
	return err
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// get Inv_uuid from InvitationMap
	inv_id := userdata.InvitationMap[filename]
	// pull the invitation from datastore via Inv_uuid
	InviteBytes, ok := userlib.DatastoreGet(inv_id)
	if !ok {
		return nil
	}
	// hybrid decrypt and verify the invitation
	VerifyKey, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(userdata.Username+"_inv_verify"))))
	if !ok {
		return nil
	}
	invitation, err := HybridVerifyThenDecrypt(userdata.Dec_inv_key, VerifyKey, InviteBytes, inv_id)
	if err != nil {
		return nil
	}
	var invite Invitation
	err = json.Unmarshal(invitation, &invite)
	if err != nil {
		return nil
	}
	// verify invitation is owner's
	if !invite.Owner {
		return nil
	}
	// pull file from datastore via invitation key
	var file_id = invite.File_uuid
	var file_dec_key = invite.Dec_file_key
	var file_ver_key = invite.Verify_file_key
	encrypted_file_struct, ok := userlib.DatastoreGet(file_id)
	if !ok {
		return nil
	}
	// hybrid decrypt and verify the file
	file_bytes, err := HybridVerifyThenDecrypt(file_dec_key, file_ver_key,encrypted_file_struct, file_id)
	var file_struct File_struct
	json.Unmarshal(file_bytes, &file_struct)
	// append content to file struct contents
	var file_list = file_struct.Contents
	var tail_ptr = file_list.Tail
	new_node := LL_Node{Prev: tail_ptr, Next: nil, Contents: content}
	*tail_ptr.Next = new_node
	file_list.Tail = &new_node
	file_struct.Num_bytes += len(content)
	new_file_bytes, err := json.Marshal(file_struct)
	if err != nil {
		return nil
	}
	// encrypt and sign file
	// put in datastore
	file_enc_key := userdata.FileEncMap[filename]
	file_sign_key := userdata.FileSignMap[filename]
	HybridEncryptThenSign(file_enc_key, file_sign_key, new_file_bytes, file_id)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// get Inv_uuid from InvitationMap
	inv_id := userdata.InvitationMap[filename]
	// pull the invitation from datastore via Inv_uuid
	InviteBytes, ok := userlib.DatastoreGet(inv_id)
	if !ok {
		return
	}
	// hybrid decrypt and verify the invitation
	VerifyKey, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(userdata.Username+"_inv_verify"))))
	if !ok {
		return
	}
	invitation, err := HybridVerifyThenDecrypt(userdata.Dec_inv_key, VerifyKey, InviteBytes, inv_id)
	if err != nil {
		return
	}
	var invite Invitation
	err = json.Unmarshal(invitation, &invite)
	if err != nil {
		return
	}
	// pull file from datastore via invitation key
	var file_id = invite.File_uuid
	var file_dec_key = invite.Dec_file_key
	var file_ver_key = invite.Verify_file_key
	encrypted_file_struct, ok := userlib.DatastoreGet(file_id)
	if !ok {
		return
	}
	// hybrid decrypt and verify the file
	file_bytes, err := HybridVerifyThenDecrypt(file_dec_key, file_ver_key,encrypted_file_struct, file_id)
	var file_struct File_struct
	json.Unmarshal(file_bytes, &file_struct)
	// iterate through contents, return contents as a list
	var file_list = file_struct.Contents
	var head = file_list.Head
	// get all of the contents
	for curr := head; curr != nil; curr = curr.Next {
		content = append(content, curr.Contents...)
	}
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// get Inv_uuid from InvitationMap
	inv_id := userdata.InvitationMap[filename]
	// pull the invitation from datastore via Inv_uuid
	InviteBytes, ok := userlib.DatastoreGet(inv_id)
	if !ok {
		return
	}
	// hybrid decrypt and verify the invitation
	VerifyKey, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(userdata.Username+"_inv_verify"))))
	if !ok {
		return
	}
	invitation, err := HybridVerifyThenDecrypt(userdata.Dec_inv_key, VerifyKey, InviteBytes, inv_id)
	if err != nil {
		return
	}
	var invite Invitation
	err = json.Unmarshal(invitation, &invite)
	if err != nil {
		return
	}
	// pull file from datastore via invitation key
	var file_id = invite.File_uuid
	var file_dec_key = invite.Dec_file_key
	var file_ver_key = invite.Verify_file_key
	encrypted_file_struct, ok := userlib.DatastoreGet(file_id)
	if !ok {
		return
	}
	// hybrid decrypt and verify the file
	file_bytes, err := HybridVerifyThenDecrypt(file_dec_key, file_ver_key,encrypted_file_struct, file_id)
	if err != nil {
		return
	}
	var file_struct File_struct
	json.Unmarshal(file_bytes, &file_struct)
	// generate random invite uuid
	new_inv_uuid := uuid.New()
	Invite := Invitation{File_uuid: file_id, 
		Dec_file_key: invite.Dec_file_key, 
		Verify_file_key: invite.Verify_file_key, 
		User: recipientUsername, 
		Filetree_uuid: invite.Filetree_uuid, 
		Sym_filetree_key: invite.Sym_filetree_key, 
		Sign_filetree_key: invite.Sign_filetree_key, 
		Verify_filetree_key: invite.Verify_filetree_key,
		Owner: false,
		Accepted: false}

	// encrypt and sign invite under recipient's public key from keystore
	new_inv_bytes, err := json.Marshal(Invite)
	recipient_key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(recipientUsername+"_inv_enc"))))
	if !ok {
		return 
	}
	HybridEncryptThenSign(recipient_key, userdata.Sign_inv_key, new_inv_bytes, new_inv_uuid)
	return new_inv_uuid, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// get invitation from datastore
	inv_bytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return nil
	}
	// verify the invitation, decrypt with userdata private key 
	VerifyKey, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(senderUsername+"_inv_verify"))))
	if !ok {
		return nil
	}
	invitation, err := HybridVerifyThenDecrypt(userdata.Dec_inv_key, VerifyKey, inv_bytes, invitationPtr)
	if err != nil {
		return nil
	}
	// unmarshal the invitation
	if err != nil {
		return nil
	}
	var invite Invitation
	err = json.Unmarshal(invitation, &invite)
	if err != nil {
		return nil
	}
	// Change the accepted boolean to true
	invite.Accepted = true
	// Store the inv_uuid in the recipient’s InvitationMap
	userdata.InvitationMap[filename]=invitationPtr
	// get the filetree from datastore
	filetree_id := invite.Filetree_uuid
	filetree_bytes, ok := userlib.DatastoreGet(filetree_id)
	if !ok {
		return nil
	}
	var filetree Tree
	json.Unmarshal(filetree_bytes, &filetree)
	// add user to the tree
	filetree.InsertNewUser(senderUsername, userdata.Username)
	// re-encrypt and re-sign with keys in the invitation
	FileTreeBytes, err := json.Marshal(filetree)
	if err != nil {
		return nil
	}
	cipher := userlib.SymEnc(invite.Sym_filetree_key, userlib.RandomBytes(16), FileTreeBytes)
	// store it in datastore with key = Filetree_uuid
	userlib.DatastoreSet(invite.Filetree_uuid, cipher)
	// Encrypt and sign the invitation struct, and store it in Datastore again
	enc_key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(userdata.Username+"_inv_enc"))))
	if !ok {
		return nil
	} 
	new_inv_bytes, err := json.Marshal(invite)
	HybridEncryptThenSign(enc_key, userdata.Sign_inv_key, new_inv_bytes, invitationPtr)
	return err
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// get Inv_uuid from InvitationMap
	inv_id := userdata.InvitationMap[filename]
	// pull the invitation from datastore via Inv_uuid
	InviteBytes, ok := userlib.DatastoreGet(inv_id)
	if !ok {
		return nil
	}
	// hybrid decrypt and verify the invitation
	VerifyKey, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(userdata.Username+"_inv_verify"))))
	if !ok {
		return nil
	}
	invitation, err := HybridVerifyThenDecrypt(userdata.Dec_inv_key, VerifyKey, InviteBytes, inv_id)
	if err != nil {
		return nil
	}
	var invite Invitation
	err = json.Unmarshal(invitation, &invite)
	if err != nil {
		return nil
	}
	// verify invitation is owner's
	if !invite.Owner {
		return nil
	} 
	// load up the file
	// pull file from datastore via invitation key
	var file_id = invite.File_uuid
	var file_dec_key = invite.Dec_file_key
	var file_ver_key = invite.Verify_file_key
	encrypted_file_struct, ok := userlib.DatastoreGet(file_id)
	if !ok {
		return nil
	}
	// hybrid decrypt and verify the file
	file_bytes, err := HybridVerifyThenDecrypt(file_dec_key, file_ver_key,encrypted_file_struct, file_id)
	var file_struct File_struct
	json.Unmarshal(file_bytes, &file_struct)
	// get the filetree from invite
	filetree_id := invite.Filetree_uuid
	filetree_bytes, ok := userlib.DatastoreGet(filetree_id)
	if !ok {
		return nil
	}
	var filetree Tree
	json.Unmarshal(filetree_bytes, &filetree)
	// Call filetree.cut_branch(user)
	filetree.RemoveUserBranch(recipientUsername)
	// Call filetree.createlist() 
	remainingUsers := filetree.GetKeys()
	// generate RSA keypair
	Encryption_key_RSA, Decryption_key_RSA, err := userlib.PKEKeyGen()
	if err != nil {
		return nil
	}
	
	// place the encryption key in the user’s FileEncMap 
	userdata.FileEncMap[filename] = Encryption_key_RSA
	// place the decryption key (Dec_file_key) in the file’s Invitation.
	
	// generate a pair of file digital signature keys
	DS_signKey, DS_verifyKey, err := userlib.DSKeyGen()
	// place the sign key in FileSignMap 
	userdata.FileSignMap[filename] = DS_signKey
	// place the verification key (Verify_file_key) in the file’s Invitation. 

	// Store file in Datastore

	// Regenerate filetree uuid and filetree keys
	// Store filetree in Datastore
	// Delete old file from datastore
	// Delete old filetree from datastore
	// Iterate through list of inv_uuids/user 
	// update invitations by creating new invitations 
	// map them to previous (same) inv_uuid (encrypt then mac with the user’s PK in keystore)


	// new_inv_uuid := uuid.New()
	// Invite := Invitation{File_uuid: file_id, 
	// 	Dec_file_key: invite.Dec_file_key, 
	// 	Verify_file_key: invite.Verify_file_key, 
	// 	User: recipientUsername, 
	// 	Filetree_uuid: invite.Filetree_uuid, 
	// 	Sym_filetree_key: invite.Sym_filetree_key, 
	// 	Sign_filetree_key: invite.Sign_filetree_key, 
	// 	Verify_filetree_key: invite.Verify_filetree_key,
	// 	Owner: false,
	// 	Accepted: false}
}