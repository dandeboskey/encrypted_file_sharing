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
	return
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

type Node struct {
	Prev     *Node
	Next     *Node
	Contents []byte
}

type LL struct {
	Head *Node
	Tail *Node
}

type File_struct struct {
	File_LL   LL
	Num_bytes int
}

type AccessPoint struct {
	User            string
	Owner           string
	File_uuid       uuid.UUID
	Sym_file_key    []byte
	Sign_file_key   userlib.PrivateKeyType
	Verify_file_key userlib.PublicKeyType
}

// Type Invitation struct

type Invitation struct {
	AXS_uuid       uuid.UUID
	Dec_AXS_key    userlib.PKEDecKey
	Verify_AXS_key userlib.PublicKeyType
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username              string
	Sym_user_key          []byte
	User_uuid             uuid.UUID
	Dec_inv_key           userlib.PKEDecKey
	Sign_inv_key          userlib.PrivateKeyType
	SharedAccessPointMap  map[string][]uuid.UUID
	AccessPointEncryptMap map[string]userlib.PKEEncKey
	AccessPointSignMap    map[string]userlib.PrivateKeyType
	UserAccessPointMap    map[string]uuid.UUID
	AccessPointDecryptMap map[string]userlib.PKEDecKey
	AccessPointVerifyMap  map[string]userlib.PublicKeyType
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
	// generate sym_user_key
	userdata.Sym_user_key = userlib.Argon2Key(password_bytes, salt_bytes, 16)
	// generate uuid from rootkey
	userdata.User_uuid, err = uuid.FromBytes(userdata.Sym_user_key)
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

	userdata.SharedAccessPointMap = make(map[string][]uuid.UUID)
	userdata.AccessPointEncryptMap = make(map[string]userlib.PKEEncKey)
	userdata.AccessPointSignMap = make(map[string]userlib.PrivateKeyType)
	userdata.UserAccessPointMap = make(map[string]uuid.UUID)
	userdata.AccessPointDecryptMap = make(map[string]userlib.PKEDecKey)
	userdata.AccessPointVerifyMap = make(map[string]userlib.PublicKeyType)

	// symmetric encryption then signing user struct
	userdata_bytes, err := json.Marshal(userdata)
	if err != nil {
		return
	}
	var userdata_cipher = userlib.SymEnc(userdata.Sym_user_key, userlib.RandomBytes(16), userdata_bytes)
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
	userlib.DatastoreSet(userdata.User_uuid, user_array_store)
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// generate sym_user_key for user
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
	sym_user_key := userlib.Argon2Key(password_bytes, salt_bytes, 16)
	// get the user uuid
	user_id, err := uuid.FromBytes(sym_user_key)
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
	key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(username + "_user_verify"))))
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
	var plaintext = userlib.SymDec(sym_user_key, cipher)
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
	// generate random accesspoint uuid
	axs_id := uuid.New()

	// generate RSA pair for accesspoint
	AXS_RSA_encKey, AXS_RSA_decKey, err := userlib.PKEKeyGen()
	if err != nil {
		return
	}
	// generate DS pair for accesspoint
	AXS_DS_signKey, AXS_DS_verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return
	}

	// generate random sym key for file
	random_bytes := userlib.RandomBytes(16)
	salt_bytes := userlib.RandomBytes(16)
	File_sym_key := userlib.Argon2Key(random_bytes, salt_bytes, 16)
	// generate DS pair for file
	File_DS_signKey, File_DS_verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return
	}

	// store info in owner's maps
	userdata.UserAccessPointMap[filename] = axs_id
	userdata.AccessPointEncryptMap[filename] = AXS_RSA_encKey
	userdata.AccessPointDecryptMap[filename] = AXS_RSA_decKey
	userdata.AccessPointSignMap[filename] = AXS_DS_signKey
	userdata.AccessPointVerifyMap[filename] = AXS_DS_verifyKey

	var AXS_list []uuid.UUID
	AXS_list = append(AXS_list, axs_id)
	userdata.SharedAccessPointMap[filename] = AXS_list

	// create file struct
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	var numBytes int
	numBytes = len(contentBytes)
	LL_Node := Node{Prev: nil, Next: nil, Contents: contentBytes}
	File_list := LL{Head: &LL_Node, Tail: &LL_Node}

	FileStruct := File_struct{File_LL: File_list,
		Num_bytes: numBytes,
	}

	// create accesspoint for owner
	AXS := AccessPoint{User: userdata.Username,
		Owner:           userdata.Username,
		File_uuid:       file_id,
		Sym_file_key:    File_sym_key,
		Sign_file_key:   File_DS_signKey,
		Verify_file_key: File_DS_verifyKey}

	// store file struct after encrypting with symmetric key and signing with DS key
	FileBytes, err := json.Marshal(FileStruct)
	if err != nil {
		return
	}
	var filedata_cipher = userlib.SymEnc(File_sym_key, userlib.RandomBytes(16), FileBytes)
	filedata_signature, err := userlib.DSSign(File_DS_signKey, filedata_cipher)
	if err != nil {
		return
	}
	file_array := make([]interface{}, 2)
	file_array[0] = filedata_cipher
	file_array[1] = filedata_signature
	file_array_store, err := json.Marshal(file_array)
	if err != nil {
		return
	}
	userlib.DatastoreSet(file_id, file_array_store)

	// store accesspoint struct after hybrid encryption and signing
	AXSBytes, err := json.Marshal(AXS)
	if err != nil {
		return
	}
	err = HybridEncryptThenSign(AXS_RSA_encKey, AXS_DS_signKey, AXSBytes, axs_id)
	if err != nil {
		return
	}
	return err
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// get axs_id from UserAccessPointMap
	axs_id := userdata.UserAccessPointMap[filename]

	// pull the accesspoint from datastore
	AXSBytes, ok := userlib.DatastoreGet(axs_id)
	if !ok {
		return nil
	}
	// hybrid verify and decrypt the accesspoint
	AXS_decKey := userdata.AccessPointDecryptMap[filename]
	AXS_verifyKey := userdata.AccessPointVerifyMap[filename]
	axs, err := HybridVerifyThenDecrypt(AXS_decKey, AXS_verifyKey, AXSBytes, axs_id)
	if err != nil {
		return nil
	}
	var AXS AccessPoint
	err = json.Unmarshal(axs, &AXS)
	if err != nil {
		return nil
	}

	// pull file from datastore
	file_id := AXS.File_uuid
	file_sym_key := AXS.Sym_file_key
	file_sign_key := AXS.Sign_file_key
	file_verify_key := AXS.Verify_file_key
	encrypted_file_struct, ok := userlib.DatastoreGet(file_id)
	if !ok {
		return nil
	}
	// verify and decrypt file struct
	var realdummy = make([]interface{}, 2)
	json.Unmarshal(encrypted_file_struct, &realdummy)
	var verification_ds = realdummy[1].([]byte)
	var cipher = realdummy[0].([]byte)
	err = userlib.DSVerify(file_verify_key, cipher, verification_ds)
	if err != nil {
		return nil
	}
	var plaintext = userlib.SymDec(file_sym_key, cipher)
	var file_struct File_struct
	// set file_struct to the unencrypted and verified file struct
	err = json.Unmarshal(plaintext, &file_struct)
	if err != nil {
		return nil
	}

	// append content to file struct contents
	var file_list = file_struct.File_LL
	var tail_ptr = file_list.Tail
	new_node := Node{Prev: tail_ptr, Next: nil, Contents: content}
	*tail_ptr.Next = new_node
	file_list.Tail = &new_node
	file_struct.Num_bytes += len(content)
	// encrypt and sign file
	FileBytes, err := json.Marshal(file_struct)
	if err != nil {
		return nil
	}
	var filedata_cipher = userlib.SymEnc(file_sym_key, userlib.RandomBytes(16), FileBytes)
	filedata_signature, err := userlib.DSSign(file_sign_key, filedata_cipher)
	if err != nil {
		return nil
	}
	file_array := make([]interface{}, 2)
	file_array[0] = filedata_cipher
	file_array[1] = filedata_signature
	file_array_store, err := json.Marshal(file_array)
	if err != nil {
		return nil
	}
	userlib.DatastoreSet(file_id, file_array_store)
	// put in datastore
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// get axs_id from UserAccessPointMap
	axs_id := userdata.UserAccessPointMap[filename]

	// pull the accesspoint from datastore
	AXSBytes, ok := userlib.DatastoreGet(axs_id)
	if !ok {
		return
	}
	// hybrid verify and decrypt the accesspoint
	AXS_decKey := userdata.AccessPointDecryptMap[filename]
	AXS_verifyKey := userdata.AccessPointVerifyMap[filename]
	axs, err := HybridVerifyThenDecrypt(AXS_decKey, AXS_verifyKey, AXSBytes, axs_id)
	if err != nil {
		return
	}
	var AXS AccessPoint
	err = json.Unmarshal(axs, &AXS)
	if err != nil {
		return
	}

	// pull file from datastore
	file_id := AXS.File_uuid
	file_sym_key := AXS.Sym_file_key
	file_verify_key := AXS.Verify_file_key
	encrypted_file_struct, ok := userlib.DatastoreGet(file_id)
	if !ok {
		return
	}
	// verify and decrypt file struct
	var realdummy = make([]interface{}, 2)
	json.Unmarshal(encrypted_file_struct, &realdummy)
	var verification_ds = realdummy[1].([]byte)
	var cipher = realdummy[0].([]byte)
	err = userlib.DSVerify(file_verify_key, cipher, verification_ds)
	if err != nil {
		return
	}
	var plaintext = userlib.SymDec(file_sym_key, cipher)
	var file_struct File_struct
	// set file_struct to the unencrypted and verified file struct
	err = json.Unmarshal(plaintext, &file_struct)
	if err != nil {
		return
	}

	// iterate through contents, return contents as a list
	var file_list = file_struct.File_LL
	var head = file_list.Head
	// get all of the contents
	for curr := head; curr != nil; curr = curr.Next {
		content = append(content, curr.Contents...)
	}
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) {
	// create random inv_id
	inv_id := uuid.New()

	// check if owner is calling the function to do this, check their access point and compare owner string
	// get axs_id from UserAccessPointMap
	axs_id := userdata.UserAccessPointMap[filename]

	// pull the accesspoint from datastore
	AXSBytes, ok := userlib.DatastoreGet(axs_id)
	if !ok {
		return
	}
	// hybrid verify and decrypt the accesspoint
	AXS_decKey := userdata.AccessPointDecryptMap[filename]
	AXS_verifyKey := userdata.AccessPointVerifyMap[filename]
	axs, err := HybridVerifyThenDecrypt(AXS_decKey, AXS_verifyKey, AXSBytes, axs_id)
	if err != nil {
		return
	}
	var AXS AccessPoint
	err = json.Unmarshal(axs, &AXS)
	if err != nil {
		return
	}
	// if non-owner calls function, share current accesspoint info in invitation.
	if AXS.Owner != userdata.Username {
		Invite := Invitation{AXS_uuid: axs_id,
			Dec_AXS_key:    AXS_decKey,
			Verify_AXS_key: AXS_verifyKey}
		inv_enc_key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(recipientUsername + "_inv_enc"))))
		if !ok {
			return
		}
		InviteBytes, err := json.Marshal(Invite)
		if err != nil {
			return
		}
		err = HybridEncryptThenSign(inv_enc_key, userdata.Sign_inv_key, InviteBytes, inv_id)
		if err != nil {
			return
		}
	}
	// if owner calls function, have to create new accesspoint
	newAXS_id := uuid.New()
	newAXS := AccessPoint{
		User:            recipientUsername,
		Owner:           userdata.Username,
		File_uuid:       AXS.File_uuid,
		Sym_file_key:    AXS.Sym_file_key,
		Verify_file_key: AXS.Verify_file_key,
		Sign_file_key:   AXS.Sign_file_key,
	}
	// generate new RSA enc and DS keys for new AXS
	newAXS_RSA_encKey, newAXS_RSA_decKey, err := userlib.PKEKeyGen()
	if err != nil {
		return
	}
	// generate DS pair for accesspoint
	newAXS_DS_signKey, newAXS_DS_verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return
	}
	// store info in owner's maps (id and the 4 keys)
	userdata.UserAccessPointMap[filename] = newAXS_id
	userdata.AccessPointEncryptMap[filename] = newAXS_RSA_encKey
	userdata.AccessPointDecryptMap[filename] = newAXS_RSA_decKey
	userdata.AccessPointSignMap[filename] = newAXS_DS_signKey
	userdata.AccessPointVerifyMap[filename] = newAXS_DS_verifyKey

	AXS_list := userdata.SharedAccessPointMap[filename]
	AXS_list = append(AXS_list, newAXS_id)
	userdata.SharedAccessPointMap[filename] = AXS_list

	// encrypt, sign, and store newAXS in Datastore
	newAXSBytes, err := json.Marshal(newAXS)
	if err != nil {
		return
	}
	err = HybridEncryptThenSign(newAXS_RSA_encKey, newAXS_DS_signKey, newAXSBytes, newAXS_id)
	if err != nil {
		return
	}

	// create invitation for this new accesspoint
	Invite := Invitation{AXS_uuid: newAXS_id,
		Dec_AXS_key:    newAXS_RSA_decKey,
		Verify_AXS_key: newAXS_DS_verifyKey}

	// encrpt, sign, and store Invite in Datastore
	inv_enc_key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(recipientUsername + "_inv_enc"))))
	if !ok {
		return
	}
	InviteBytes, err := json.Marshal(Invite)
	if err != nil {
		return
	}
	err = HybridEncryptThenSign(inv_enc_key, userdata.Sign_inv_key, InviteBytes, inv_id)
	if err != nil {
		return
	}
	// re-store user struct
	newUserDS_signKey, newUserDS_verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return
	}
	userlib.KeystoreSet(string(userlib.Hash([]byte(userdata.Username+"_user_verify"))), newUserDS_verifyKey)
	userdata_bytes, err := json.Marshal(userdata)
	if err != nil {
		return
	}
	var userdata_cipher = userlib.SymEnc(userdata.Sym_user_key, userlib.RandomBytes(16), userdata_bytes)
	userdata_signature, err := userlib.DSSign(newUserDS_signKey, userdata_cipher)
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
	userlib.DatastoreSet(userdata.User_uuid, user_array_store)
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// get invitation from datastore
	inv_bytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return nil
	}
	// verify the invitation, decrypt with userdata private key
	VerifyKey, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(senderUsername + "_inv_verify"))))
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
	// store invitation data in user's maps
	userdata.UserAccessPointMap[filename] = invite.AXS_uuid
	userdata.AccessPointDecryptMap[filename] = invite.Dec_AXS_key
	userdata.AccessPointVerifyMap[filename] = invite.Verify_AXS_key
	// re-encrypt user struct with sym key, re-sign user struct with new DS pair, and overwrite verification key in keystore
	newUserDS_signKey, newUserDS_verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil
	}
	userlib.KeystoreSet(string(userlib.Hash([]byte(userdata.Username+"_user_verify"))), newUserDS_verifyKey)
	userdata_bytes, err := json.Marshal(userdata)
	if err != nil {
		return nil
	}
	var userdata_cipher = userlib.SymEnc(userdata.Sym_user_key, userlib.RandomBytes(16), userdata_bytes)
	userdata_signature, err := userlib.DSSign(newUserDS_signKey, userdata_cipher)
	if err != nil {
		return nil
	}
	user_array := make([]interface{}, 2)
	user_array[0] = userdata_cipher
	user_array[1] = userdata_signature
	user_array_store, err := json.Marshal(user_array)
	if err != nil {
		return nil
	}
	userlib.DatastoreSet(userdata.User_uuid, user_array_store)
	return err
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	return nil
}
