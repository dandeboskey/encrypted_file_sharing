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

type HybridData struct {
	Ciphertext      []byte
	Verification    []byte
	EncryptedSymKey []byte
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
		return err
	}
	// Encrypt the symmetric key
	enc_sym_key, err := userlib.PKEEnc(enc_key, key)
	if err != nil {
		return err
	}
	// Create an array with (encrypted data, signature, encrypted symmetric key)
	user_array := HybridData{
		Ciphertext:      ciphertext,
		Verification:    signed,
		EncryptedSymKey: enc_sym_key,
	}
	// Marshal the array
	user_array_store, err := json.Marshal(user_array)
	if err != nil {
		return err
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
	// Unmarshal the data
	var realData HybridData
	err = json.Unmarshal(enc_data, &realData)
	if err != nil {
		return
	}
	ciphertext := realData.Ciphertext
	verification := realData.Verification
	encrypted_sym_key := realData.EncryptedSymKey
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
	// Decrypt the encrypted data with the decrypted symmetric key
	new_data := userlib.SymDec(sym_key, ciphertext)
	return new_data, err
}

type Node struct {
	Contents []byte
	Next     uuid.UUID
	End      bool
}

type File_struct struct {
	HeadNode_uuid uuid.UUID
	TailNode_uuid uuid.UUID
	Num_bytes     int
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
	Username       string
	Sym_user_key   []byte
	User_uuid      uuid.UUID
	Sign_user_key  userlib.PrivateKeyType
	Dec_inv_key    userlib.PKEDecKey
	Sign_inv_key   userlib.PrivateKeyType
	User_map_id    uuid.UUID
	Enc_map_key    userlib.PKEEncKey
	Dec_map_key    userlib.PKEDecKey
	Sign_map_key   userlib.PrivateKeyType
	Verify_map_key userlib.PublicKeyType
}

type UserMaps struct {
	SharedAccessPointMap  map[string][]uuid.UUID
	AccessPointEncryptMap map[uuid.UUID]userlib.PKEEncKey
	AccessPointSignMap    map[uuid.UUID]userlib.PrivateKeyType
	UserAccessPointMap    map[string]uuid.UUID
	AccessPointDecryptMap map[uuid.UUID]userlib.PKEDecKey
	AccessPointVerifyMap  map[uuid.UUID]userlib.PublicKeyType
}

type UserData struct {
	UserdataCipher    []byte
	UserdataSignature []byte
}

type FileData struct {
	FiledataCipher    []byte
	FiledataSignature []byte
}

type NodeData struct {
	NodedataCiphertext []byte
	NodedataSignature  []byte
}

type FileUsers struct {
	FileUsersCiphertext []byte
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
	userdataptr = &userdata
	if username == "" {
		return userdataptr, errors.New("empty username")
	}
	if password == "" {
		return userdataptr, errors.New("empty password")
	}
	_, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(username + "_user_verify"))))
	if ok {
		return userdataptr, errors.New("user with specified username already exists")
	}
	var password_bytes, salt_bytes []byte
	password_bytes, err = json.Marshal(userlib.Hash([]byte(username + password)))
	if err != nil {
		return userdataptr, err
	}
	salt_bytes, err = json.Marshal(1) // salt = 1 for determinism
	if err != nil {
		return userdataptr, err
	}
	userdata.Username = username
	// generate sym_user_key
	userdata.Sym_user_key = userlib.Argon2Key(password_bytes, salt_bytes, 16)
	// generate uuid from rootkey
	userdata.User_uuid, err = uuid.FromBytes(userdata.Sym_user_key)
	if err != nil {
		return userdataptr, err
	}
	// generate DS key pairs for sign & verify user struct
	var DS_verify_key userlib.PublicKeyType
	var DS_sign_key userlib.DSSignKey
	DS_sign_key, DS_verify_key, err = userlib.DSKeyGen()
	if err != nil {
		return userdataptr, err
	}
	// put verification key in keystore: hash(username + “_user_verify”):Verify_user_key
	userlib.KeystoreSet(string(userlib.Hash([]byte(username+"_user_verify"))), DS_verify_key)
	// put sign key in user struct (for self)
	userdata.Sign_user_key = DS_sign_key

	// generate RSA key pair for encrypting and decrypting invitations
	var Enc_inv_key userlib.PKEEncKey
	Enc_inv_key, userdata.Dec_inv_key, err = userlib.PKEKeyGen()
	// put invitation encryption key in keystore: hash(username + “_inv_enc”):Enc_inv_key
	userlib.KeystoreSet(string(userlib.Hash([]byte(username+"_inv_enc"))), Enc_inv_key)
	// generate DS key pairs for sign & verify invitations
	var inv_verify_key userlib.DSVerifyKey
	userdata.Sign_inv_key, inv_verify_key, err = userlib.DSKeyGen()
	if err != nil {
		return userdataptr, err
	}
	// put invitation verification key in keystore: hash(username + “_inv_verify”):Verify_inv_key
	userlib.KeystoreSet(string(userlib.Hash([]byte(username+"_inv_verify"))), inv_verify_key)

	// set up user's maps
	userdata.Enc_map_key, userdata.Dec_map_key, err = userlib.PKEKeyGen()
	userdata.Sign_map_key, userdata.Verify_map_key, err = userlib.DSKeyGen()
	userdata.User_map_id = uuid.New()

	user_SharedAccessPointMap := make(map[string][]uuid.UUID)
	user_AccessPointEncryptMap := make(map[uuid.UUID]userlib.PKEEncKey)
	user_AccessPointSignMap := make(map[uuid.UUID]userlib.PrivateKeyType)
	user_UserAccessPointMap := make(map[string]uuid.UUID)
	user_AccessPointDecryptMap := make(map[uuid.UUID]userlib.PKEDecKey)
	user_AccessPointVerifyMap := make(map[uuid.UUID]userlib.PublicKeyType)

	user_maps := UserMaps{SharedAccessPointMap: user_SharedAccessPointMap,
		AccessPointEncryptMap: user_AccessPointEncryptMap,
		AccessPointSignMap:    user_AccessPointSignMap,
		UserAccessPointMap:    user_UserAccessPointMap,
		AccessPointDecryptMap: user_AccessPointDecryptMap,
		AccessPointVerifyMap:  user_AccessPointVerifyMap,
	}
	user_map_bytes, err := json.Marshal(user_maps)
	if err != nil {
		return userdataptr, err
	}
	err = HybridEncryptThenSign(userdata.Enc_map_key, userdata.Sign_map_key, user_map_bytes, userdata.User_map_id)
	if err != nil {
		return userdataptr, err
	}

	// symmetric encryption then signing user struct
	userdata_bytes, err := json.Marshal(userdata)
	if err != nil {
		return userdataptr, err
	}
	var userdata_cipher = userlib.SymEnc(userdata.Sym_user_key, userlib.RandomBytes(16), userdata_bytes)
	userdata_signature, err := userlib.DSSign(DS_sign_key, userdata_cipher)
	if err != nil {
		return userdataptr, err
	}
	user_array := UserData{
		UserdataCipher:    userdata_cipher,
		UserdataSignature: userdata_signature,
	}
	user_array_store, err := json.Marshal(user_array)
	if err != nil {
		return userdataptr, err
	}

	userlib.DatastoreSet(userdata.User_uuid, user_array_store)
	return userdataptr, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// generate sym_user_key for user
	var password_bytes, salt_bytes []byte
	password_bytes, err = json.Marshal(userlib.Hash([]byte(username + password)))
	if err != nil {
		return userdataptr, err
	}
	salt_bytes, err = json.Marshal(1) // salt = 1 for determinism
	if err != nil {
		return userdataptr, err
	}
	// generate root key
	sym_user_key := userlib.Argon2Key(password_bytes, salt_bytes, 16)
	// get the user uuid
	user_id, err := uuid.FromBytes(sym_user_key)
	if err != nil {
		return userdataptr, err
	}
	userBytes, ok := userlib.DatastoreGet(user_id)
	// verify that user exists in datastore
	if !ok {
		return userdataptr, errors.New("user not in datastore")
	}
	// pull encrypted & signed user struct from datastore
	var realData UserData
	err = json.Unmarshal(userBytes, &realData)
	if err != nil {
		return userdataptr, err
	}
	key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(username + "_user_verify"))))
	if !ok {
		return userdataptr, err
	}
	// verify and decrypt user struct
	verification_ds := realData.UserdataSignature
	cipher := realData.UserdataCipher
	err = userlib.DSVerify(key, cipher, verification_ds)
	if err != nil {
		return userdataptr, err
	}
	var plaintext = userlib.SymDec(sym_user_key, cipher)
	// set userdataptr to the unencrypted and verified user struct
	userdataptr = &User{}
	err = json.Unmarshal(plaintext, userdataptr)
	if err != nil {
		return userdataptr, err
	}
	return userdataptr, err
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// pull struct from datastore
	map_id := userdata.User_map_id
	map_bytes, ok := userlib.DatastoreGet(map_id)
	if !ok {
		return errors.New("cannot access map_bytes")
	}
	map_struct, err := HybridVerifyThenDecrypt(userdata.Dec_map_key, userdata.Verify_map_key, map_bytes, map_id)
	if err != nil {
		return err
	}
	var user_maps UserMaps
	err = json.Unmarshal(map_struct, &user_maps)
	if err != nil {
		return err
	}

	// check if file already exists, if so, overwrite
	old_axs_id, ok := user_maps.UserAccessPointMap[filename]
	if ok {
		// load access point
		OldAXSBytes, ok := userlib.DatastoreGet(old_axs_id)
		if !ok {
			return errors.New("AXS bytes irretrievable")
		}
		// hybrid verify and decrypt the accesspoint
		OldAXS_decKey := user_maps.AccessPointDecryptMap[old_axs_id]
		OldAXS_verifyKey := user_maps.AccessPointVerifyMap[old_axs_id]
		var old_axs []byte
		old_axs, err = HybridVerifyThenDecrypt(OldAXS_decKey, OldAXS_verifyKey, OldAXSBytes, old_axs_id)
		if err != nil {
			return err
		}
		var OldAXS AccessPoint
		err = json.Unmarshal(old_axs, &OldAXS)
		if err != nil {
			return err
		}
		// create head node and file struct
		var contentBytes []byte
		contentBytes, err = json.Marshal(content)
		if err != nil {
			return err
		}
		var numBytes int
		numBytes = len(contentBytes)
		head_id := uuid.New()

		headnode := Node{Contents: content, Next: head_id, End: true}
		FileStruct := File_struct{HeadNode_uuid: head_id, TailNode_uuid: head_id, Num_bytes: numBytes}

		// store head node and file struct with keys from access point
		old_file_id := OldAXS.File_uuid
		old_sym_key := OldAXS.Sym_file_key
		old_sign_key := OldAXS.Sign_file_key
		var HeadNodeBytes []byte
		HeadNodeBytes, err = json.Marshal(headnode)
		if err != nil {
			return err
		}
		var headnode_cipher = userlib.SymEnc(old_sym_key, userlib.RandomBytes(16), HeadNodeBytes)
		var headnode_signature []byte
		headnode_signature, err = userlib.DSSign(old_sign_key, headnode_cipher)
		if err != nil {
			return err
		}
		headnode_array := NodeData{
			NodedataCiphertext: headnode_cipher,
			NodedataSignature:  headnode_signature,
		}
		var headnode_array_store []byte
		headnode_array_store, err = json.Marshal(headnode_array)
		if err != nil {
			return
		}
		userlib.DatastoreSet(head_id, headnode_array_store)

		// store file struct after encrypting with symmetric key and signing with DS key
		FileBytes, err := json.Marshal(FileStruct)
		if err != nil {
			return err
		}
		var filedata_cipher = userlib.SymEnc(old_sym_key, userlib.RandomBytes(16), FileBytes)
		filedata_signature, err := userlib.DSSign(old_sign_key, filedata_cipher)
		if err != nil {
			return err
		}
		file_array := FileData{
			FiledataCipher:    filedata_cipher,
			FiledataSignature: filedata_signature,
		}
		file_array_store, err := json.Marshal(file_array)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(old_file_id, file_array_store)
		// return
		return err
	}

	// generate random file uuid
	file_id := uuid.New()
	// generate random accesspoint uuid
	axs_id := uuid.New()

	// generate RSA pair for accesspoint
	AXS_RSA_encKey, AXS_RSA_decKey, err := userlib.PKEKeyGen()
	if err != nil {
		return err
	}
	// generate DS pair for accesspoint
	AXS_DS_signKey, AXS_DS_verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return err
	}

	// generate random sym key for file
	random_bytes := userlib.RandomBytes(16)
	salt_bytes := userlib.RandomBytes(16)
	File_sym_key := userlib.Argon2Key(random_bytes, salt_bytes, 16)
	// generate DS pair for file
	File_DS_signKey, File_DS_verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return err
	}

	// store info in owner's maps
	user_maps.UserAccessPointMap[filename] = axs_id
	user_maps.AccessPointEncryptMap[axs_id] = AXS_RSA_encKey
	user_maps.AccessPointDecryptMap[axs_id] = AXS_RSA_decKey
	user_maps.AccessPointSignMap[axs_id] = AXS_DS_signKey
	user_maps.AccessPointVerifyMap[axs_id] = AXS_DS_verifyKey
	// we are putting the owner's accesspoint in the shared map. we don't need to do this.
	//var AXS_list []uuid.UUID
	//AXS_list = append(AXS_list, axs_id)
	//user_maps.SharedAccessPointMap[filename] = AXS_list
	// re-store struct
	user_map_bytes, err := json.Marshal(user_maps)
	if err != nil {
		return
	}
	err = HybridEncryptThenSign(userdata.Enc_map_key, userdata.Sign_map_key, user_map_bytes, userdata.User_map_id)
	if err != nil {
		return err
	}

	// create file struct
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	var numBytes int
	numBytes = len(contentBytes)
	head_id := uuid.New()

	headnode := Node{Contents: content, Next: head_id, End: true}
	FileStruct := File_struct{HeadNode_uuid: head_id, TailNode_uuid: head_id, Num_bytes: numBytes}

	// create accesspoint for owner
	AXS := AccessPoint{User: userdata.Username,
		Owner:           userdata.Username,
		File_uuid:       file_id,
		Sym_file_key:    File_sym_key,
		Sign_file_key:   File_DS_signKey,
		Verify_file_key: File_DS_verifyKey}

	// store nodes after encrypting with same symmetric and ds keys as that of the file struct
	HeadNodeBytes, err := json.Marshal(headnode)
	if err != nil {
		return err
	}
	var headnode_cipher = userlib.SymEnc(File_sym_key, userlib.RandomBytes(16), HeadNodeBytes)
	headnode_signature, err := userlib.DSSign(File_DS_signKey, headnode_cipher)
	if err != nil {
		return err
	}
	headnode_array := NodeData{
		NodedataCiphertext: headnode_cipher,
		NodedataSignature:  headnode_signature,
	}
	headnode_array_store, err := json.Marshal(headnode_array)
	if err != nil {
		return
	}
	userlib.DatastoreSet(head_id, headnode_array_store)

	// store file struct after encrypting with symmetric key and signing with DS key
	FileBytes, err := json.Marshal(FileStruct)
	if err != nil {
		return err
	}
	var filedata_cipher = userlib.SymEnc(File_sym_key, userlib.RandomBytes(16), FileBytes)
	filedata_signature, err := userlib.DSSign(File_DS_signKey, filedata_cipher)
	if err != nil {
		return err
	}
	file_array := FileData{
		FiledataCipher:    filedata_cipher,
		FiledataSignature: filedata_signature,
	}
	file_array_store, err := json.Marshal(file_array)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(file_id, file_array_store)

	// store accesspoint struct after hybrid encryption and signing
	AXSBytes, err := json.Marshal(AXS)
	if err != nil {
		return err
	}
	err = HybridEncryptThenSign(AXS_RSA_encKey, AXS_DS_signKey, AXSBytes, axs_id)
	if err != nil {
		return err
	}

	// re-store user struct because maps were modified
	DS_sign_key := userdata.Sign_user_key
	if err != nil {
		return err
	}
	userdata_bytes, err := json.Marshal(userdata)
	if err != nil {
		return err
	}
	var userdata_cipher = userlib.SymEnc(userdata.Sym_user_key, userlib.RandomBytes(16), userdata_bytes)
	userdata_signature, err := userlib.DSSign(DS_sign_key, userdata_cipher)
	if err != nil {
		return err
	}
	user_array := UserData{
		UserdataCipher:    userdata_cipher,
		UserdataSignature: userdata_signature,
	}
	user_array_store, err := json.Marshal(user_array)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(userdata.User_uuid, user_array_store)

	// for revoke access, to check if invitation was accepted
	file_users := []string{}
	file_users = append(file_users, userdata.Username)
	file_users_bytes, err := json.Marshal(file_users)
	if err != nil {
		return err
	}
	file_users_password_bytes, err := json.Marshal(file_id)
	if err != nil {
		return err
	}
	file_users_salt_bytes, err := json.Marshal(1) // salt = 1 for determinism
	if err != nil {
		return err
	}
	file_users_sym_key := userlib.Argon2Key(file_users_password_bytes, file_users_salt_bytes, 16)
	file_users_uuid, err := uuid.FromBytes(file_users_sym_key)
	if err != nil {
		return err
	}
	file_users_cipher := userlib.SymEnc(file_users_sym_key, userlib.RandomBytes(16), file_users_bytes)
	file_users_array := FileUsers{
		FileUsersCiphertext: file_users_cipher}
	file_users_array_store, err := json.Marshal(file_users_array)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(file_users_uuid, file_users_array_store)
	return err
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// pull map struct -> we do not modify in this function so no need to re-store at the end
	map_id := userdata.User_map_id
	map_bytes, ok := userlib.DatastoreGet(map_id)
	if !ok {
		return errors.New("Map bytes irretrievable")
	}
	map_struct, err := HybridVerifyThenDecrypt(userdata.Dec_map_key, userdata.Verify_map_key, map_bytes, map_id)
	if err != nil {
		return err
	}
	var user_maps UserMaps
	err = json.Unmarshal(map_struct, &user_maps)
	if err != nil {
		return err
	}
	// get axs_id from UserAccessPointMap
	axs_id := user_maps.UserAccessPointMap[filename]
	// pull the accesspoint from datastore
	AXSBytes, ok := userlib.DatastoreGet(axs_id)
	if !ok {
		return errors.New("AXS bytes irretrievable")
	}
	// hybrid verify and decrypt the accesspoint
	AXS_decKey := user_maps.AccessPointDecryptMap[axs_id]
	AXS_verifyKey := user_maps.AccessPointVerifyMap[axs_id]
	axs, err := HybridVerifyThenDecrypt(AXS_decKey, AXS_verifyKey, AXSBytes, axs_id)
	if err != nil {
		return err
	}
	var AXS AccessPoint
	err = json.Unmarshal(axs, &AXS)
	if err != nil {
		return err
	}

	// pull file from datastore
	file_id := AXS.File_uuid
	file_sym_key := AXS.Sym_file_key
	file_sign_key := AXS.Sign_file_key
	file_verify_key := AXS.Verify_file_key
	encrypted_file_struct, ok := userlib.DatastoreGet(file_id)
	if !ok {
		return errors.New("File irretrievable")
	}
	// verify and decrypt file struct
	var RealData FileData
	json.Unmarshal(encrypted_file_struct, &RealData)
	var verification_ds = RealData.FiledataSignature
	var cipher = RealData.FiledataCipher
	err = userlib.DSVerify(file_verify_key, cipher, verification_ds)
	if err != nil {
		return err
	}
	var plaintext = userlib.SymDec(file_sym_key, cipher)
	var file_struct File_struct
	// set file_struct to the unencrypted and verified file struct
	err = json.Unmarshal(plaintext, &file_struct)
	if err != nil {
		return err
	}
	// append content to file struct contents
	if file_struct.HeadNode_uuid == file_struct.TailNode_uuid {
		encrypted_head_node, ok := userlib.DatastoreGet(file_struct.HeadNode_uuid)
		if !ok {
			return errors.New("Node bytes irretrievable")
		}
		// verify and decrypt file struct
		var HeadData NodeData
		json.Unmarshal(encrypted_head_node, &HeadData)
		headverification_ds := HeadData.NodedataSignature
		headcipher := HeadData.NodedataCiphertext
		err = userlib.DSVerify(file_verify_key, headcipher, headverification_ds)
		if err != nil {
			return err
		}
		var plaintext = userlib.SymDec(file_sym_key, headcipher)
		var head_node Node
		// set head_node to the unencrypted and verified file struct
		err = json.Unmarshal(plaintext, &head_node)
		if err != nil {
			return err
		}
		// create new tail node for appended content
		new_tail_id := uuid.New()
		new_tail := Node{Contents: content, Next: new_tail_id, End: true}
		head_node.End = false
		head_node.Next = new_tail_id
		file_struct.TailNode_uuid = new_tail_id
		file_struct.Num_bytes += len(content)
		// encrypt and sign head
		HeadBytes, err := json.Marshal(head_node)
		if err != nil {
			return err
		}
		var headnode_cipher = userlib.SymEnc(file_sym_key, userlib.RandomBytes(16), HeadBytes)
		headnode_signature, err := userlib.DSSign(file_sign_key, headnode_cipher)
		if err != nil {
			return err
		}
		head_array := NodeData{
			NodedataCiphertext: headnode_cipher,
			NodedataSignature:  headnode_signature,
		}
		head_array_store, err := json.Marshal(head_array)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(file_struct.HeadNode_uuid, head_array_store)
		// encrypt and sign new tail
		TailBytes, err := json.Marshal(new_tail)
		if err != nil {
			return err
		}
		var tailnode_cipher = userlib.SymEnc(file_sym_key, userlib.RandomBytes(16), TailBytes)
		tailnode_signature, err := userlib.DSSign(file_sign_key, tailnode_cipher)
		if err != nil {
			return err
		}
		tail_array := NodeData{
			NodedataCiphertext: tailnode_cipher,
			NodedataSignature:  tailnode_signature,
		}
		tail_array_store, err := json.Marshal(tail_array)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(new_tail_id, tail_array_store)
		// encrypt and sign file struct
		FileBytes, err := json.Marshal(file_struct)
		if err != nil {
			return err
		}
		var filedata_cipher = userlib.SymEnc(file_sym_key, userlib.RandomBytes(16), FileBytes)
		filedata_signature, err := userlib.DSSign(file_sign_key, filedata_cipher)
		if err != nil {
			return err
		}
		file_array := FileData{
			FiledataCipher:    filedata_cipher,
			FiledataSignature: filedata_signature,
		}
		file_array_store, err := json.Marshal(file_array)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(file_id, file_array_store)
		return nil
	} else {
		oldtail_id := file_struct.TailNode_uuid
		encrypted_tail_node, ok := userlib.DatastoreGet(file_struct.TailNode_uuid)
		if !ok {
			return errors.New("Node bytes irretrievable")
		}
		// verify and decrypt file struct
		var TailData NodeData
		json.Unmarshal(encrypted_tail_node, &TailData)
		var verification_ds = TailData.NodedataSignature
		var cipher = TailData.NodedataCiphertext
		err = userlib.DSVerify(file_verify_key, cipher, verification_ds)
		if err != nil {
			return err
		}
		var plaintext = userlib.SymDec(file_sym_key, cipher)
		var tail_node Node
		// set tail_node to the unencrypted and verified file struct
		err = json.Unmarshal(plaintext, &tail_node)
		if err != nil {
			return err
		}
		// create new tail node for appended content
		new_tail_id := uuid.New()
		new_tail := Node{Contents: content, Next: new_tail_id, End: true}
		tail_node.End = false
		tail_node.Next = new_tail_id
		file_struct.TailNode_uuid = new_tail_id
		file_struct.Num_bytes += len(content)
		// encrypt and sign old tail
		OldTailBytes, err := json.Marshal(tail_node)
		if err != nil {
			return err
		}
		var oldtailnode_cipher = userlib.SymEnc(file_sym_key, userlib.RandomBytes(16), OldTailBytes)
		oldtailnode_signature, err := userlib.DSSign(file_sign_key, oldtailnode_cipher)
		if err != nil {
			return err
		}
		oldtail_array := NodeData{
			NodedataCiphertext: oldtailnode_cipher,
			NodedataSignature:  oldtailnode_signature,
		}
		oldtail_array_store, err := json.Marshal(oldtail_array)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(oldtail_id, oldtail_array_store)
		// encrypt and sign new tail
		TailBytes, err := json.Marshal(new_tail)
		if err != nil {
			return err
		}
		var tailnode_cipher = userlib.SymEnc(file_sym_key, userlib.RandomBytes(16), TailBytes)
		tailnode_signature, err := userlib.DSSign(file_sign_key, tailnode_cipher)
		if err != nil {
			return err
		}
		tail_array := NodeData{
			NodedataCiphertext: tailnode_cipher,
			NodedataSignature:  tailnode_signature,
		}
		tail_array_store, err := json.Marshal(tail_array)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(new_tail_id, tail_array_store)
		// encrypt and sign file struct
		FileBytes, err := json.Marshal(file_struct)
		if err != nil {
			return err
		}
		var filedata_cipher = userlib.SymEnc(file_sym_key, userlib.RandomBytes(16), FileBytes)
		filedata_signature, err := userlib.DSSign(file_sign_key, filedata_cipher)
		if err != nil {
			return err
		}
		file_array := FileData{
			FiledataCipher:    filedata_cipher,
			FiledataSignature: filedata_signature,
		}
		file_array_store, err := json.Marshal(file_array)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(file_id, file_array_store)
		return nil
	}
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// pull map struct -> we do not modify in this function so no need to re-store at the end
	content = []byte{}
	map_id := userdata.User_map_id
	map_bytes, ok := userlib.DatastoreGet(map_id)
	if !ok {
		return content, errors.New("AXS bytes irretrievable")
	}
	map_struct, err := HybridVerifyThenDecrypt(userdata.Dec_map_key, userdata.Verify_map_key, map_bytes, map_id)
	if err != nil {
		return content, err
	}
	var user_maps UserMaps
	err = json.Unmarshal(map_struct, &user_maps)
	if err != nil {
		return content, err
	}
	// get axs_id from UserAccessPointMap
	// fmt.Println(userdata.Username)
	// fmt.Println(filename)
	axs_id := user_maps.UserAccessPointMap[filename]
	// fmt.Println(axs_id)
	// pull the accesspoint from datastore
	AXSBytes, ok := userlib.DatastoreGet(axs_id)
	// fmt.Println(AXSBytes)
	if !ok {
		return content, errors.New("AXS bytes irretrievable")
	}
	// hybrid verify and decrypt the accesspoint
	AXS_decKey := user_maps.AccessPointDecryptMap[axs_id]
	AXS_verifyKey := user_maps.AccessPointVerifyMap[axs_id]
	axs, err := HybridVerifyThenDecrypt(AXS_decKey, AXS_verifyKey, AXSBytes, axs_id)
	if err != nil {
		return content, err
	}
	var AXS AccessPoint
	err = json.Unmarshal(axs, &AXS)
	if err != nil {
		return content, err
	}
	// fmt.Println(AXS)

	// pull file from datastore
	file_id := AXS.File_uuid
	// fmt.Println(file_id)
	file_sym_key := AXS.Sym_file_key
	file_verify_key := AXS.Verify_file_key
	encrypted_file_struct, ok := userlib.DatastoreGet(file_id)
	if !ok {
		return content, errors.New("file s irretrievable")
	}
	// verify and decrypt file struct
	var RealData FileData
	json.Unmarshal(encrypted_file_struct, &RealData)
	var verification_ds = RealData.FiledataSignature
	var cipher = RealData.FiledataCipher
	err = userlib.DSVerify(file_verify_key, cipher, verification_ds)
	if err != nil {
		return content, err
	}
	var plaintext = userlib.SymDec(file_sym_key, cipher)
	var file_struct File_struct
	// set file_struct to the unencrypted and verified file struct
	err = json.Unmarshal(plaintext, &file_struct)
	if err != nil {
		return content, err
	}

	// load head node
	head_id := file_struct.HeadNode_uuid
	// fmt.Println(head_id)
	encrypted_head_node, ok := userlib.DatastoreGet(head_id)
	var HeadData NodeData
	json.Unmarshal(encrypted_head_node, &HeadData)
	var head_verification = HeadData.NodedataSignature
	var head_cipher = HeadData.NodedataCiphertext
	err = userlib.DSVerify(file_verify_key, head_cipher, head_verification)
	if err != nil {
		return content, err
	}
	var plainhead = userlib.SymDec(file_sym_key, head_cipher)
	var head_node Node
	err = json.Unmarshal(plainhead, &head_node)

	curr := head_node
	// iterate through contents, return contents as a list
	// get all of the contents
	for !curr.End {
		content = append(content, curr.Contents...)
		next_id := curr.Next
		encrypted_next_node, ok := userlib.DatastoreGet(next_id)
		if !ok {
			return content, err
		}
		var NextData NodeData
		json.Unmarshal(encrypted_next_node, &NextData)
		var next_verification = NextData.NodedataSignature
		var next_cipher = NextData.NodedataCiphertext
		err = userlib.DSVerify(file_verify_key, next_cipher, next_verification)
		if err != nil {
			return content, err
		}
		var plainnext = userlib.SymDec(file_sym_key, next_cipher)
		var next_node Node
		err = json.Unmarshal(plainnext, &next_node)
		curr = next_node
	}
	content = append(content, curr.Contents...)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationptr uuid.UUID, err error) {
	// create random inv_id
	inv_id := uuid.New()
	invitationptr = inv_id
	// pull map struct
	map_id := userdata.User_map_id
	map_bytes, ok := userlib.DatastoreGet(map_id)
	if !ok {
		return invitationptr, errors.New("cannot access map bytes")
	}
	map_struct, err := HybridVerifyThenDecrypt(userdata.Dec_map_key, userdata.Verify_map_key, map_bytes, map_id)
	if err != nil {
		return invitationptr, err
	}
	var user_maps UserMaps
	err = json.Unmarshal(map_struct, &user_maps)
	if err != nil {
		return invitationptr, err
	}

	// check if owner is calling the function to do this, check their access point and compare owner string
	// get axs_id from UserAccessPointMap
	axs_id := user_maps.UserAccessPointMap[filename]
	// pull the accesspoint from datastore
	AXSBytes, ok := userlib.DatastoreGet(axs_id)
	if !ok {
		return invitationptr, errors.New("cannot access axsbytes")
	}
	// hybrid verify and decrypt the accesspoint
	AXS_decKey := user_maps.AccessPointDecryptMap[axs_id]
	AXS_verifyKey := user_maps.AccessPointVerifyMap[axs_id]
	axs, err := HybridVerifyThenDecrypt(AXS_decKey, AXS_verifyKey, AXSBytes, axs_id)
	if err != nil {
		return invitationptr, err
	}
	var AXS AccessPoint
	err = json.Unmarshal(axs, &AXS)
	if err != nil {
		return invitationptr, err
	}
	// if non-owner calls function, share current accesspoint info in invitation.
	if AXS.Owner != userdata.Username {
		Invite := Invitation{AXS_uuid: axs_id,
			Dec_AXS_key:    AXS_decKey,
			Verify_AXS_key: AXS_verifyKey}
		inv_enc_key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(recipientUsername + "_inv_enc"))))
		if !ok {
			return invitationptr, errors.New("no inv_enc_key")
		}
		var InviteBytes []byte
		InviteBytes, err = json.Marshal(Invite)
		if err != nil {
			return invitationptr, err
		}
		err = HybridEncryptThenSign(inv_enc_key, userdata.Sign_inv_key, InviteBytes, inv_id)
		if err != nil {
			return invitationptr, err
		}
		invitationptr = inv_id
		return invitationptr, err
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
		return invitationptr, err
	}
	// generate DS pair for accesspoint
	newAXS_DS_signKey, newAXS_DS_verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return invitationptr, err
	}
	// store info in owner's maps (id and the 4 keys)
	user_maps.UserAccessPointMap[filename] = axs_id
	user_maps.AccessPointEncryptMap[newAXS_id] = newAXS_RSA_encKey
	user_maps.AccessPointDecryptMap[newAXS_id] = newAXS_RSA_decKey
	user_maps.AccessPointSignMap[newAXS_id] = newAXS_DS_signKey
	user_maps.AccessPointVerifyMap[newAXS_id] = newAXS_DS_verifyKey

	AXS_list := user_maps.SharedAccessPointMap[filename]
	AXS_list = append(AXS_list, newAXS_id)
	user_maps.SharedAccessPointMap[filename] = AXS_list

	// re-store user_maps due to modifications
	user_map_bytes, err := json.Marshal(user_maps)
	if err != nil {
		return invitationptr, err
	}
	err = HybridEncryptThenSign(userdata.Enc_map_key, userdata.Sign_map_key, user_map_bytes, userdata.User_map_id)
	if err != nil {
		return invitationptr, err
	}

	// encrypt, sign, and store newAXS in Datastore
	newAXSBytes, err := json.Marshal(newAXS)
	if err != nil {
		return invitationptr, err
	}
	err = HybridEncryptThenSign(newAXS_RSA_encKey, newAXS_DS_signKey, newAXSBytes, newAXS_id)
	if err != nil {
		return invitationptr, err
	}

	// create invitation for this new accesspoint
	Invite := Invitation{AXS_uuid: newAXS_id,
		Dec_AXS_key:    newAXS_RSA_decKey,
		Verify_AXS_key: newAXS_DS_verifyKey}

	// encrpt, sign, and store Invite in Datastore
	inv_enc_key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(recipientUsername + "_inv_enc"))))
	if !ok {
		return invitationptr, errors.New("cannot get inv_enc_key")
	}
	InviteBytes, err := json.Marshal(Invite)
	if err != nil {
		return invitationptr, err
	}
	err = HybridEncryptThenSign(inv_enc_key, userdata.Sign_inv_key, InviteBytes, inv_id)
	if err != nil {
		return invitationptr, err
	}
	// re-store user struct
	DS_sign_key := userdata.Sign_user_key
	if err != nil {
		return invitationptr, err
	}
	userdata_bytes, err := json.Marshal(userdata)
	if err != nil {
		return invitationptr, err
	}
	var userdata_cipher = userlib.SymEnc(userdata.Sym_user_key, userlib.RandomBytes(16), userdata_bytes)
	userdata_signature, err := userlib.DSSign(DS_sign_key, userdata_cipher)
	if err != nil {
		return invitationptr, err
	}
	user_array := UserData{
		UserdataCipher:    userdata_cipher,
		UserdataSignature: userdata_signature,
	}
	user_array_store, err := json.Marshal(user_array)
	if err != nil {
		return invitationptr, err
	}
	userlib.DatastoreSet(userdata.User_uuid, user_array_store)
	//invitationptr = inv_id
	return invitationptr, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// pull map struct
	map_id := userdata.User_map_id
	map_bytes, ok := userlib.DatastoreGet(map_id)
	if !ok {
		return errors.New("cannot access map_bytes")
	}
	map_struct, err := HybridVerifyThenDecrypt(userdata.Dec_map_key, userdata.Verify_map_key, map_bytes, map_id)
	if err != nil {
		return err
	}
	var user_maps UserMaps
	err = json.Unmarshal(map_struct, &user_maps)
	if err != nil {
		return err
	}
	// get invitation from datastore
	inv_bytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("cannot access inv_bytes")
	}
	// verify the invitation, decrypt with userdata private key
	VerifyKey, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(senderUsername + "_inv_verify"))))
	if !ok {
		return errors.New("cannot access key")
	}
	invitation, err := HybridVerifyThenDecrypt(userdata.Dec_inv_key, VerifyKey, inv_bytes, invitationPtr)
	if err != nil {
		return err
	}
	// unmarshal the invitation
	if err != nil {
		return err
	}
	var invite Invitation
	err = json.Unmarshal(invitation, &invite)
	if err != nil {
		return err
	}
	// store invitation data in user's maps
	if _, isMapContainsKey := user_maps.UserAccessPointMap[filename]; isMapContainsKey {
		//key exist
		return errors.New("filename already exists in user space")
	} 
	user_maps.UserAccessPointMap[filename] = invite.AXS_uuid
	user_maps.AccessPointDecryptMap[invite.AXS_uuid] = invite.Dec_AXS_key
	user_maps.AccessPointVerifyMap[invite.AXS_uuid] = invite.Verify_AXS_key

	// load AXS to get file_id
	AXSBytes, ok := userlib.DatastoreGet(invite.AXS_uuid)
	if !ok {
		return errors.New("AXS bytes irretrievable")
	}
	AXS_decKey := user_maps.AccessPointDecryptMap[invite.AXS_uuid]
	AXS_verifyKey := user_maps.AccessPointVerifyMap[invite.AXS_uuid]
	axs, err := HybridVerifyThenDecrypt(AXS_decKey, AXS_verifyKey, AXSBytes, invite.AXS_uuid)
	if err != nil {
		return err
	}
	var AXS AccessPoint
	err = json.Unmarshal(axs, &AXS)
	if err != nil {
		return err
	}
	file_id := AXS.File_uuid
	// add recipient to file_users struct in datastore
	file_users_password_bytes, err := json.Marshal(file_id)
	if err != nil {
		return err
	}
	file_users_salt_bytes, err := json.Marshal(1) // salt = 1 for determinism
	if err != nil {
		return err
	}
	file_users_sym_key := userlib.Argon2Key(file_users_password_bytes, file_users_salt_bytes, 16)
	file_users_uuid, err := uuid.FromBytes(file_users_sym_key)
	file_users_bytes, ok := userlib.DatastoreGet(file_users_uuid)
	// verify that file_users exists in datastore
	if !ok {
		return errors.New("file_users not in datastore")
	}
	// pull encrypted file_users struct from datastore
	var file_users_data FileUsers
	err = json.Unmarshal(file_users_bytes, &file_users_data)
	if err != nil {
		return err
	}
	// decrypt file_users struct
	cipher := file_users_data.FileUsersCiphertext
	var plaintext = userlib.SymDec(file_users_sym_key, cipher)
	var file_users []string
	err = json.Unmarshal(plaintext, &file_users)
	if err != nil {
		return err
	}
	file_users = append(file_users, userdata.Username)
	// re-encrypt and re-store in datastore
	file_users_bytes, err = json.Marshal(file_users)
	if err != nil {
		return err
	}
	file_users_cipher := userlib.SymEnc(file_users_sym_key, userlib.RandomBytes(16), file_users_bytes)
	if err != nil {
		return err
	}
	file_users_array := FileUsers{
		FileUsersCiphertext: file_users_cipher}
	file_users_array_store, err := json.Marshal(file_users_array)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(file_users_uuid, file_users_array_store)

	// re-store user_maps
	user_map_bytes, err := json.Marshal(user_maps)
	if err != nil {
		return err
	}
	err = HybridEncryptThenSign(userdata.Enc_map_key, userdata.Sign_map_key, user_map_bytes, userdata.User_map_id)
	if err != nil {
		return err
	}
	// re-encrypt user struct with sym key, re-sign user struct with new DS pair, and overwrite verification key in keystore
	// re-store user struct
	DS_sign_key := userdata.Sign_user_key
	if err != nil {
		return err
	}
	userdata_bytes, err := json.Marshal(userdata)
	if err != nil {
		return err
	}
	var userdata_cipher = userlib.SymEnc(userdata.Sym_user_key, userlib.RandomBytes(16), userdata_bytes)
	userdata_signature, err := userlib.DSSign(DS_sign_key, userdata_cipher)
	if err != nil {
		return err
	}
	user_array := UserData{
		UserdataCipher:    userdata_cipher,
		UserdataSignature: userdata_signature,
	}
	user_array_store, err := json.Marshal(user_array)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(userdata.User_uuid, user_array_store)
	return err
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	_, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(recipientUsername + "_user_verify"))))
	if !ok {
		return errors.New("recipient user does not exist")
	}
	// pull map struct
	map_id := userdata.User_map_id
	map_bytes, ok := userlib.DatastoreGet(map_id)
	if !ok {
		return errors.New("Can't get the map from Datastore")
	}
	map_struct, err := HybridVerifyThenDecrypt(userdata.Dec_map_key, userdata.Verify_map_key, map_bytes, map_id)
	if err != nil {
		return err
	}
	var user_maps UserMaps
	err = json.Unmarshal(map_struct, &user_maps)
	if err != nil {
		return err
	}
	// Load their access point and check that they’re the owner
	axs_id := user_maps.UserAccessPointMap[filename]
	AXSBytes, ok := userlib.DatastoreGet(axs_id)
	if !ok {
		return errors.New("AXS bytes irretrievable")
	}
	AXS_decKey := user_maps.AccessPointDecryptMap[axs_id]
	AXS_verifyKey := user_maps.AccessPointVerifyMap[axs_id]
	axs, err := HybridVerifyThenDecrypt(AXS_decKey, AXS_verifyKey, AXSBytes, axs_id)
	if err != nil {
		return err
	}
	var AXS AccessPoint
	err = json.Unmarshal(axs, &AXS)
	if err != nil {
		return err
	}
	if AXS.Owner != userdata.Username {
		return err
	}
	file_id := AXS.File_uuid
	// check if recipientUser accepted invite
	file_users_password_bytes, err := json.Marshal(file_id)
	if err != nil {
		return err
	}
	file_users_salt_bytes, err := json.Marshal(1) // salt = 1 for determinism
	if err != nil {
		return err
	}
	file_users_sym_key := userlib.Argon2Key(file_users_password_bytes, file_users_salt_bytes, 16)
	file_users_uuid, err := uuid.FromBytes(file_users_sym_key)
	file_users_bytes, ok := userlib.DatastoreGet(file_users_uuid)
	// verify that file_users exists in datastore
	if !ok {
		return errors.New("file_users not in datastore")
	}
	// pull encrypted file_users struct from datastore
	var file_users_data FileUsers
	err = json.Unmarshal(file_users_bytes, &file_users_data)
	if err != nil {
		return err
	}
	// decrypt file_users struct
	file_users_cipher := file_users_data.FileUsersCiphertext
	file_users_plaintext := userlib.SymDec(file_users_sym_key, file_users_cipher)
	var file_users []string
	err = json.Unmarshal(file_users_plaintext, &file_users)
	if err != nil {
		return err
	}
	check := false
	for _, val := range file_users {
		if val == recipientUsername {
			check = true
		}
	}
	if check == false {
		return errors.New("cannot revoke access on user")
	}
	// Go to the user that you’re trying to revoke and get their access point from the map
	removed := false
	access_point_ids := user_maps.SharedAccessPointMap[filename]
	for i, val := range access_point_ids {
		cur_axs_id := val
		cur_axs_bytes, ok := userlib.DatastoreGet(cur_axs_id)
		if !ok {
			return errors.New("cur AXS bytes irretrievable")
		}
		cur_AXS_decKey := user_maps.AccessPointDecryptMap[cur_axs_id]
		cur_AXS_verifyKey := user_maps.AccessPointVerifyMap[cur_axs_id]
		cur_axs, err := HybridVerifyThenDecrypt(cur_AXS_decKey, cur_AXS_verifyKey, cur_axs_bytes, cur_axs_id)
		if err != nil {
			return err
		}
		var cur_AXS AccessPoint
		err = json.Unmarshal(cur_axs, &cur_AXS)
		if err != nil {
			return err
		}
		// Remove accesspoint from shared map list and delete the access point from datastore
		if cur_AXS.User == recipientUsername {
			access_point_ids = append(access_point_ids[:i], access_point_ids[i+1:]...)
			userlib.DatastoreDelete(cur_axs_id)
			removed = true
			// also remove from file_users share list
			for j, u := range file_users {
				if u == recipientUsername {
					file_users = append(file_users[:j], file_users[j+1:]...)
					break
				}
			}
			// re-store file_users in datastore
			file_users_bytes, err = json.Marshal(file_users)
			if err != nil {
				return err
			}
			file_users_cipher := userlib.SymEnc(file_users_sym_key, userlib.RandomBytes(16), file_users_bytes)
			if err != nil {
				return err
			}
			file_users_array := FileUsers{
				FileUsersCiphertext: file_users_cipher}
			file_users_array_store, err := json.Marshal(file_users_array)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(file_users_uuid, file_users_array_store)
			break
		}
	}
	if removed == false {
		return errors.New("user cannot be revoked")
	}
	user_maps.SharedAccessPointMap[filename] = access_point_ids

	// load file using old data (about to modify id and keys)
	file_id = AXS.File_uuid
	file_sym_key := AXS.Sym_file_key
	file_verify_key := AXS.Verify_file_key
	encrypted_file_struct, ok := userlib.DatastoreGet(file_id)
	if !ok {
		return errors.New("file struct irretrievable")
	}
	// verify and decrypt file struct
	var RealData FileData
	json.Unmarshal(encrypted_file_struct, &RealData)
	var verification_ds = RealData.FiledataSignature
	var cipher = RealData.FiledataCipher
	err = userlib.DSVerify(file_verify_key, cipher, verification_ds)
	if err != nil {
		return err
	}
	var plaintext = userlib.SymDec(file_sym_key, cipher)
	var file_struct File_struct
	// set file_struct to the unencrypted and verified file struct
	err = json.Unmarshal(plaintext, &file_struct)
	if err != nil {
		return err
	}
	// new enc dec key for file and its nodes
	random_bytes := userlib.RandomBytes(16)
	salt_bytes := userlib.RandomBytes(16)
	new_file_symKey := userlib.Argon2Key(random_bytes, salt_bytes, 16)
	// generate DS pair for file and its nodes
	new_file_signKey, new_file_verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return err
	}
	// re-encrypt, re-sign, and re-store every node of the file in datastore, must create new ids for each and update as we iterate
	// remember we use old keys to load and new keys to store
	// load head node
	head_id := file_struct.HeadNode_uuid
	encrypted_head_node, ok := userlib.DatastoreGet(head_id)
	var HeadData NodeData
	json.Unmarshal(encrypted_head_node, &HeadData)
	var head_verification = HeadData.NodedataSignature
	var head_cipher = HeadData.NodedataCiphertext
	err = userlib.DSVerify(file_verify_key, head_cipher, head_verification)
	if err != nil {
		return err
	}
	var plainhead = userlib.SymDec(file_sym_key, head_cipher)
	var head_node Node
	err = json.Unmarshal(plainhead, &head_node)
	curr := head_node
	// iterate through
	var old_next_id uuid.UUID
	var new_next_id uuid.UUID
	if !curr.End {
		for !curr.End {
			new_cur_id := uuid.New()
			if head_id == new_cur_id {
				file_struct.HeadNode_uuid = new_cur_id
			}
			old_next_id = curr.Next
			new_next_id = uuid.New()
			curr.Next = new_next_id
			// store current node in datastore
			currNodeBytes, err := json.Marshal(curr)
			if err != nil {
				return err
			}
			var currnode_cipher = userlib.SymEnc(new_file_symKey, userlib.RandomBytes(16), currNodeBytes)
			currode_signature, err := userlib.DSSign(new_file_signKey, currnode_cipher)
			if err != nil {
				return err
			}
			currnode_array := NodeData{
				NodedataCiphertext: currnode_cipher,
				NodedataSignature:  currode_signature,
			}
			currnode_array_store, err := json.Marshal(currnode_array)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(new_cur_id, currnode_array_store)
			// load next node from datastore
			encrypted_next_node, ok := userlib.DatastoreGet(old_next_id)
			if !ok {
				return errors.New("encrypted_next_node irretrievable")
			}
			var NextData NodeData
			json.Unmarshal(encrypted_next_node, &NextData)
			var next_verification = NextData.NodedataSignature
			var next_cipher = NextData.NodedataCiphertext
			err = userlib.DSVerify(file_verify_key, next_cipher, next_verification)
			if err != nil {
				return err
			}
			var plainnext = userlib.SymDec(file_sym_key, next_cipher)
			var next_node Node
			err = json.Unmarshal(plainnext, &next_node)
			curr = next_node
		}
		// load tail ptr (curr.End == true)
		//old_tail_id := old_next_id
		/** new_tail_id := new_next_id
		file_struct.TailNode_uuid = new_tail_id
		encrypted_tail_node, ok := userlib.DatastoreGet(new_next_id)
		if !ok {
			fmt.Println("err")
			return err
		}
		var TailData NodeData
		json.Unmarshal(encrypted_tail_node, &TailData)
		var tail_verification = TailData.NodedataSignature
		var tail_cipher = TailData.NodedataCiphertext
		err = userlib.DSVerify(file_verify_key, tail_cipher, tail_verification)
		if err != nil {
			return err
		}
		var plaintail = userlib.SymDec(file_sym_key, tail_cipher)
		var tail_node Node
		err = json.Unmarshal(plaintail, &tail_node) */
		tail_node := curr
		tail_node.Next = new_next_id
		// re-store tail node with new keys and id
		newTailBytes, err := json.Marshal(tail_node)
		if err != nil {
			return err
		}
		var newTail_cipher = userlib.SymEnc(new_file_symKey, userlib.RandomBytes(16), newTailBytes)
		newTail_sig, err := userlib.DSSign(new_file_signKey, newTail_cipher)
		if err != nil {
			return err
		}
		newTail_array := NodeData{
			NodedataCiphertext: newTail_cipher,
			NodedataSignature:  newTail_sig,
		}
		newTail_array_store, err := json.Marshal(newTail_array)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(new_next_id, newTail_array_store)
	} else { // only one node in the file
		var new_id = uuid.New()
		file_struct.HeadNode_uuid = new_id
		file_struct.TailNode_uuid = new_id
		currNodeBytes, err := json.Marshal(curr)
		if err != nil {
			return err
		}
		var currnode_cipher = userlib.SymEnc(new_file_symKey, userlib.RandomBytes(16), currNodeBytes)
		currode_signature, err := userlib.DSSign(new_file_signKey, currnode_cipher)
		if err != nil {
			return err
		}
		currnode_array := NodeData{
			NodedataCiphertext: currnode_cipher,
			NodedataSignature:  currode_signature,
		}
		currnode_array_store, err := json.Marshal(currnode_array)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(new_id, currnode_array_store)
	}
	// now, store file struct
	new_file_id := uuid.New()
	FileBytes, err := json.Marshal(file_struct)
	if err != nil {
		return err
	}
	var filedata_cipher = userlib.SymEnc(new_file_symKey, userlib.RandomBytes(16), FileBytes)
	filedata_signature, err := userlib.DSSign(new_file_signKey, filedata_cipher)
	if err != nil {
		return err
	}
	file_array := FileData{
		FiledataCipher:    filedata_cipher,
		FiledataSignature: filedata_signature,
	}
	file_array_store, err := json.Marshal(file_array)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(new_file_id, file_array_store)
	//  update owner's access point, re-encrypt re-sign and store with same axs_id
	userlib.DatastoreDelete(axs_id)
	newAXS := AccessPoint{
		User:            userdata.Username,
		Owner:           userdata.Username,
		File_uuid:       new_file_id,
		Sym_file_key:    new_file_symKey,
		Verify_file_key: new_file_verifyKey,
		Sign_file_key:   new_file_signKey,
	}
	// userdata.UserAccessPointMap[filename] = newAXS_id
	var axs_bytes []byte
	axs_bytes, err = json.Marshal(newAXS)
	if err != nil {
		return err
	}
	AXS_encKey := user_maps.AccessPointEncryptMap[axs_id]
	AXS_signKey := user_maps.AccessPointSignMap[axs_id]
	err = HybridEncryptThenSign(AXS_encKey, AXS_signKey, axs_bytes, axs_id)
	if err != nil {
		return err
	}

	//  update remaining access points, re-encrypt re-sign and store
	new_access_point_ids := user_maps.SharedAccessPointMap[filename]
	for _, val := range new_access_point_ids {
		cur_axs_id := val
		cur_axs_bytes, ok := userlib.DatastoreGet(cur_axs_id)
		if !ok {
			return errors.New("cur AXS bytes irretrievable")
		}
		cur_AXS_decKey := user_maps.AccessPointDecryptMap[cur_axs_id]
		cur_AXS_verifyKey := user_maps.AccessPointVerifyMap[cur_axs_id]
		cur_axs, err := HybridVerifyThenDecrypt(cur_AXS_decKey, cur_AXS_verifyKey, cur_axs_bytes, cur_axs_id)
		if err != nil {
			return err
		}
		var cur_AXS AccessPoint
		err = json.Unmarshal(cur_axs, &cur_AXS)
		if err != nil {
			return err
		}
		recipient := cur_AXS.User
		newAXS := AccessPoint{
			User:            recipient,
			Owner:           userdata.Username,
			File_uuid:       new_file_id,
			Sym_file_key:    new_file_symKey,
			Verify_file_key: new_file_verifyKey,
			Sign_file_key:   new_file_signKey,
		}
		axs_bytes, err = json.Marshal(newAXS)
		if err != nil {
			return err
		}
		userlib.DatastoreDelete(cur_axs_id)
		cur_AXS_encKey := user_maps.AccessPointEncryptMap[cur_axs_id]
		cur_AXS_signKey := user_maps.AccessPointSignMap[cur_axs_id]
		err = HybridEncryptThenSign(cur_AXS_encKey, cur_AXS_signKey, axs_bytes, cur_axs_id)
		if err != nil {
			return err
		}
	}
	// re-store map struct
	user_map_bytes, err := json.Marshal(user_maps)
	if err != nil {
		return err
	}
	err = HybridEncryptThenSign(userdata.Enc_map_key, userdata.Sign_map_key, user_map_bytes, userdata.User_map_id)
	if err != nil {
		return err
	}
	// 	re-encrypt re-sign and store owner struct (map was modified)
	DS_sign_key := userdata.Sign_user_key
	if err != nil {
		return err
	}
	userdata_bytes, err := json.Marshal(userdata)
	if err != nil {
		return err
	}
	var userdata_cipher = userlib.SymEnc(userdata.Sym_user_key, userlib.RandomBytes(16), userdata_bytes)
	userdata_signature, err := userlib.DSSign(DS_sign_key, userdata_cipher)
	if err != nil {
		return err
	}
	user_array := UserData{
		UserdataCipher:    userdata_cipher,
		UserdataSignature: userdata_signature,
	}
	user_array_store, err := json.Marshal(user_array)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(userdata.User_uuid, user_array_store)
	return err
}
