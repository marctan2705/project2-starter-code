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

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct { //encrypted

	Username string;
	Argon2Key []byte; // Argon2Key	
	PKEDecKey userlib.PKEDecKey; // Private key for public key encryption
	DSSignKey userlib.DSSignKey;// Private key for signing
	AccessControlUUID uuid.UUID; // AccessControlUUID points to AccessControl struct
	ACKey []byte
	// which contains FileMap
}

type keyStruct struct {
	key []byte;
	fileUUID uuid.UUID;
}

type AccessControl struct { // this struct is encrypted
	FileMap map[string][]byte; // dictionary of pointers to file blocks (keys of maps == fileName)
	KeyStructMap map[string][]byte; // dictionary of KeyStructs for encrypted file blocks
}

type FileContent struct { // this struct is encrypted
	KeyMap map[string][]byte; // keys to decrypt and mac contentblocks in contentList
	// ContentList: []byte; // array of pointers to content blocks
	UserMap map[string][]string; // map of (parent: [child1, child2, ...])
	lastBlock uuid.UUID;
	// MACMap: []byte // array of MACs for ContentBlocks in ContentList (MACs now stored in bytestring)
	}

type ContentBlock struct{
	ENContent []byte; // content to be decrypted to KNOWLEDGE
	prevBlock uuid.UUID;
}

type InvitationBlock struct{
	KeyStructUUID uuid.UUID;
}

//helper functions
func macandencrypt(key []byte, AC []byte) (ACto []byte) {
	AChashKey, err := userlib.HashKDF(key, []byte("enc"))
	print(err)
	r := userlib.RandomBytes(16)
	ACpointer := userlib.SymEnc(AChashKey[:16], r, AC)
	ACmacKey, err := userlib.HashKDF(key, []byte("mac"))
	ACMAC, err := userlib.HMACEval(ACmacKey, ACpointer)
	ACto = []byte(string(ACMAC) + string(ACpointer))
	return ACto
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	// all the user stuff
	var userdata User
	for(len(username) < 16){
		username = username + "0"
	}
	userdata.Username = username
	bytePassword := []byte(password)
	byteUsername := []byte(username)
	key := userlib.Argon2Key(bytePassword, byteUsername, 16)?
	if(err != nil){
		print(err)
	}
	userdata.Argon2Key = key
	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()
	UUID := uuid.Must(uuid.FromBytes(byteUsername))
	userdata.DSSignKey = DSSignKey
	PKEEncKey, PKEDecKey, err := userlib.PKEKeyGen()
	if(err != nil){
		print(err)
	}
	userdata.PKEDecKey = PKEDecKey
	userlib.KeystoreSet(username + " PKEEncKey", PKEEncKey)
	userlib.KeystoreSet(username + " DSVerifyKey", DSVerifyKey)

	// lets create access control stuff
	ACUUID := uuid.New()
	var AC AccessControl
	ACkey := userlib.RandomBytes(16)
	ACenc, err := json.Marshal(AC)
	print(err)
	ACto := macandencrypt(ACkey, ACenc)
	userlib.DatastoreSet(ACUUID, ACto)

	// adding access control to the user
	userdata.AccessControlUUID = ACUUID
	userdata.ACKey = ACkey

	//saving the user
	userenc, err := json.Marshal(userdata)
	print(err)
	userto := macandencrypt(key, userenc)
	userlib.DatastoreSet(UUID, userto)



	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
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
