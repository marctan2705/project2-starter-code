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

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct { //encrypted

	Username          string
	Argon2Key         []byte            // Argon2Key
	PKEDecKey         userlib.PKEDecKey // Private key for public key encryption
	DSSignKey         userlib.DSSignKey // Private key for signing
	AccessControlUUID uuid.UUID         // AccessControlUUID points to AccessControl struct
	ACKey             []byte
	// which contains FileMap
}

type keyStruct struct {
	Key      []byte
	FileUUID uuid.UUID
}

type AccessControl struct { // this struct is encrypted
	KeyStructUUIDMap    map[string]uuid.UUID // dictionary of pointers to keystruct (keys of maps == fileName)
	KeyMap              map[string][]byte    // dictionary of keys used for encrypted keystruct
	OwnedFiles          map[string]string    // see which files you own
	InvitationNameMap   map[string][]string  //filename : username
	InvitationAccessMap map[string]uuid.UUID // filenameusername : uuid of keystruct
	InvitationKeyMap    map[string][]byte    //filenameusername : key
}

type FileContent struct { // this struct is encrypted
	// KeyMap map[string][]byte; // keys to decrypt and mac contentblocks in contentList
	// ContentList: []byte; // array of pointers to content blocks
	// UserMap      map[string][]string // map of (parent: [child1, child2, ...])
	LastBlock    uuid.UUID // UUID to last block
	LastBlockKey []byte    // key of last block
	// MACMap: []byte // array of MACs for ContentBlocks in ContentList (MACs now stored in bytestring)
}

type ContentBlock struct {
	ENContent    []byte // content to be decrypted to KNOWLEDGE
	PrevBlock    uuid.UUID
	PrevBlockKey []byte
}

type InvitationBlock struct {
	KeyStructUUID uuid.UUID
	Key           []byte
}

// helper functions
func macandencrypt(key []byte, AC []byte) (ACto []byte) {
	AChashKey, err := userlib.HashKDF(key, []byte("enc"))
	if err != nil {
		return nil
	}
	r := userlib.RandomBytes(16)
	ACpointer := userlib.SymEnc(AChashKey[:16], r, AC)
	ACmacKey, err := userlib.HashKDF(key, []byte("mac"))
	// print("MACKEY", ACmacKey)

	ACMAC, err := userlib.HMACEval(ACmacKey[:16], ACpointer)
	ACto = []byte(string(ACMAC) + string(ACpointer))
	return ACto
}

func signandencrypt(enckey userlib.PKEEncKey, signkey userlib.DSSignKey, AC []byte) (ACto []byte) {
	cipher, err := userlib.PKEEnc(enckey, AC)
	if err != nil {
		return nil
	}
	signature, err := userlib.DSSign(signkey, cipher)
	if err != nil {
		return nil
	}
	ACto = []byte(string(signature) + string(cipher))
	return ACto
}

func checkMAC(key []byte, ciphertext []byte, MAC []byte) (res bool, err error) {
	macKey, err := userlib.HashKDF(key, []byte("mac"))
	// print("MACKEY", macKey)
	if err != nil {
		return false, err
	}
	MACCandidate, err := userlib.HMACEval(macKey[:16], ciphertext)
	// print(MACCandidate)
	if err != nil {
		return false, err
	}
	res = userlib.HMACEqual(MACCandidate, MAC)
	return res, nil
}

func decrypt(key []byte, ciphertext []byte, MAC []byte) (decryptedFile []byte, err error) {
	truefalse, err := checkMAC(key, ciphertext, MAC)
	if err != nil {
		return nil, err
	}
	if !truefalse {
		return nil, errors.New("MAC does not match ciphertext")
	}
	enckey, err := userlib.HashKDF(key, []byte("enc"))
	if err != nil {
		return nil, err
	}
	decryptedFile = userlib.SymDec(enckey[:16], ciphertext)
	return decryptedFile, nil
}

func publicKeyDecrypt(deckey userlib.PKEDecKey, verifykey userlib.DSVerifyKey, ciphertext []byte, signature []byte) (plaintext []byte, err error) {
	err = userlib.DSVerify(verifykey, ciphertext, signature)
	if err != nil {
		return nil, err
	}
	plaintext, err = userlib.PKEDec(deckey, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, err
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	// all the user stuff
	if len(username) == 0 {
		return nil, errors.New("username is empty")
	}
	var userdata User
	byteUsername := userlib.Hash([]byte(username))[:16]
	userdata.Username = username
	bytePassword := []byte(password)
	key := userlib.Argon2Key(bytePassword, []byte(username), 16)

	if err != nil {
		return nil, err
	}
	userdata.Argon2Key = key
	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	UUID := uuid.Must(uuid.FromBytes(byteUsername))
	_, ok := userlib.DatastoreGet(UUID)
	if ok {
		return nil, errors.New("username already exists; uuid derived from username found in datastore")
	}
	userdata.DSSignKey = DSSignKey
	PKEEncKey, PKEDecKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	userdata.PKEDecKey = PKEDecKey
	userlib.KeystoreSet(username+" PKEEncKey", PKEEncKey)
	userlib.KeystoreSet(username+" DSVerifyKey", DSVerifyKey)

	// lets create access control stuff
	ACUUID := uuid.New()
	var AC AccessControl
	AC.KeyStructUUIDMap = make(map[string]uuid.UUID)
	AC.KeyMap = make(map[string][]byte)
	// AC.InvitationMap = make(map[FileUserKey][]byte)
	AC.OwnedFiles = make(map[string]string)
	AC.InvitationNameMap = make(map[string][]string)    //filename : username
	AC.InvitationAccessMap = make(map[string]uuid.UUID) // filename-username : uuid of file keystruct
	AC.InvitationKeyMap = make(map[string][]byte)       //filename-username : key
	ACkey := userlib.RandomBytes(16)
	ACenc, err := json.Marshal(AC)
	if err != nil {
		return nil, err
	}
	ACto := macandencrypt(ACkey, ACenc)
	userlib.DatastoreSet(ACUUID, ACto)

	// adding access control to the user
	userdata.AccessControlUUID = ACUUID
	userdata.ACKey = ACkey

	//saving the user
	userenc, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	userto := macandencrypt(key, userenc)
	userlib.DatastoreSet(UUID, userto)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// var userdata User
	// userdataptr = &userdata
	// print(userdataptr)
	if len(username) == 0 {
		return nil, errors.New("username is empty")
	}
	byteUsername := userlib.Hash([]byte(username))[:16]
	bytePassword := []byte(password)
	key := userlib.Argon2Key(bytePassword, []byte(username), 16)
	UUID := uuid.Must(uuid.FromBytes(byteUsername))
	cipher, ok := userlib.DatastoreGet(UUID)
	// print(cipher[64:])
	if !ok {
		return nil, errors.New("cannot find")
	}
	decFile, err := decrypt(key, cipher[64:], cipher[:64])
	if err != nil {
		return nil, err
	}
	var userdata User
	err = json.Unmarshal(decFile, &userdata)
	if err != nil {
		return nil, err
	}

	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	// if err != nil {
	// 	return err
	// }
	// contentBytes, err := json.Marshal(content)
	// if err != nil {
	// 	return err
	// }
	// userlib.DatastoreSet(storageKey, contentBytes)

	//Fetch AC

	ACUUID := userdata.AccessControlUUID
	ACenc, ok := userlib.DatastoreGet(ACUUID)
	if !ok {
		return errors.New("not found")
	}
	ACdec, err := decrypt(userdata.ACKey, ACenc[64:], ACenc[:64])
	if err != nil {
		return nil
	}
	var AC AccessControl
	err = json.Unmarshal(ACdec, &AC)
	if err != nil {
		return nil
	}
	filekey := userlib.RandomBytes(16)
	fileuuid := uuid.New()
	if keyStructUUID, ok := AC.KeyStructUUIDMap[filename]; ok {
		keyStructKey := AC.KeyMap[filename]
		keyStructd, ok := userlib.DatastoreGet(keyStructUUID)
		if !ok {
			return errors.New("not found")
		}
		keystructdec, err := decrypt(keyStructKey, keyStructd[64:], keyStructd[:64])
		if err != nil {
			return err
		}
		var keydata keyStruct
		json.Unmarshal(keystructdec, &keydata)
		fileuuid = keydata.FileUUID
		filekey = keydata.Key
	}

	//create contentBlock
	contentKey := userlib.RandomBytes(16)
	var block ContentBlock
	block.ENContent = content
	block.PrevBlock = uuid.Nil
	block.PrevBlockKey = nil
	contentenc, err := json.Marshal(block)
	if err != nil {
		return err
	}
	contentUUID := uuid.New()
	contentto := macandencrypt(contentKey, contentenc)
	userlib.DatastoreSet(contentUUID, contentto)

	//create FileContent Block
	var file FileContent
	//file.UserMap = make(map[string][]string)
	//file.UserMap[userdata.Username] = make([]string, 0)
	file.LastBlock = contentUUID
	file.LastBlockKey = contentKey

	fileenc, err := json.Marshal(file)
	if err != nil {
		return err
	}
	fileto := macandencrypt(filekey, fileenc)
	userlib.DatastoreSet(fileuuid, fileto)

	if keyStructUUID, ok := AC.KeyStructUUIDMap[filename]; ok {
		fmt.Print(keyStructUUID)
		return nil
	}

	//Create Keystruct
	keystructuuid, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16]) //owner -> userto share -> filename
	if err != nil {
		return err
	}
	var magicbox keyStruct
	magicbox.FileUUID = fileuuid
	magicbox.Key = filekey
	magicboxenc, err := json.Marshal(magicbox)
	if err != nil {
		return err
	}
	magicboxkey := userlib.RandomBytes(16)
	magicboxto := macandencrypt(magicboxkey, magicboxenc)
	userlib.DatastoreSet(keystructuuid, magicboxto)

	//put into AC
	AC.OwnedFiles[filename] = ""
	AC.KeyStructUUIDMap[filename] = keystructuuid
	AC.KeyMap[filename] = magicboxkey
	AC.InvitationNameMap[filename] = make([]string, 0)
	ACenc, err = json.Marshal(AC)
	if err != nil {
		return nil
	}
	ACto := macandencrypt(userdata.ACKey, ACenc)
	userlib.DatastoreSet(ACUUID, ACto)
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// fetch and decrypt user's AccessControl
	ACUUID := userdata.AccessControlUUID
	ACenc, ok := userlib.DatastoreGet(ACUUID)
	if !ok {
		return errors.New("not found")
	}
	ACdec, err := decrypt(userdata.ACKey, ACenc[64:], ACenc[:64])
	if err != nil {
		return errors.New("can't decrypt accesscontrol struct")
	}
	var AC AccessControl
	err = json.Unmarshal(ACdec, &AC)
	if err != nil {
		return errors.New("can't unmarshal accesscontrol struct")
	}
	keyStructUUID, ok := AC.KeyStructUUIDMap[filename]
	if !ok {
		return errors.New("can't find filename in user's keystructuuidmap")
	}
	keyStructKey, ok := AC.KeyMap[filename]
	if !ok {
		return errors.New("can't find filename in user's keymap")
	}

	// fetch and decrypt filename's KeyStruct
	keyStructEncryptedJSON, ok := userlib.DatastoreGet(keyStructUUID)
	if !ok {
		return errors.New("can't find keystruct in datastore")
	}
	keyStructDecryptedJSON, err := decrypt(keyStructKey, keyStructEncryptedJSON[64:], keyStructEncryptedJSON[:64])
	if err != nil {
		return err
	}
	var filenameKeyStruct keyStruct
	err = json.Unmarshal(keyStructDecryptedJSON, &filenameKeyStruct)
	if err != nil {
		return err
	}

	// fetch FileContent from Datastore
	fileContentEncryptedJSON, ok := userlib.DatastoreGet(filenameKeyStruct.FileUUID)
	if !ok {
		return errors.New("can't find filecontent from datastore")
	}
	fileContentDecryptedJSON, err := decrypt(filenameKeyStruct.Key, fileContentEncryptedJSON[64:], fileContentEncryptedJSON[:64])
	if err != nil {
		return err
	}
	var fileContent FileContent
	err = json.Unmarshal(fileContentDecryptedJSON, &fileContent)
	if err != nil {
		return err
	}

	//create new contentblock
	var newcontent ContentBlock
	newcontent.ENContent = content
	newcontent.PrevBlock = fileContent.LastBlock
	newcontent.PrevBlockKey = fileContent.LastBlockKey

	contentkey := userlib.RandomBytes(16)
	contentmarsh, err := json.Marshal(newcontent)
	if err != nil {
		return err
	}
	contentto := macandencrypt(contentkey, contentmarsh)
	contentuuid := uuid.New()
	userlib.DatastoreSet(contentuuid, contentto)

	fileContent.LastBlock = contentuuid
	fileContent.LastBlockKey = contentkey

	fileContentmarsh, err := json.Marshal(fileContent)
	if err != nil {
		return err
	}
	filecontento := macandencrypt(filenameKeyStruct.Key, fileContentmarsh)
	userlib.DatastoreSet(filenameKeyStruct.FileUUID, filecontento)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// fetch and decrypt user's AccessControl
	ACUUID := userdata.AccessControlUUID
	ACenc, ok := userlib.DatastoreGet(ACUUID)
	if !ok {
		return nil, errors.New("not found")
	}
	ACdec, err := decrypt(userdata.ACKey, ACenc[64:], ACenc[:64])
	if err != nil {
		return nil, errors.New("can't decrypt accesscontrol struct")
	}
	var AC AccessControl
	err = json.Unmarshal(ACdec, &AC)
	if err != nil {
		return nil, errors.New("can't unmarshal accesscontrol struct")
	}
	keyStructUUID, ok := AC.KeyStructUUIDMap[filename]
	if !ok {
		return nil, errors.New("can't find filename in user's keystructuuidmap")
	}
	keyStructKey, ok := AC.KeyMap[filename]
	if !ok {
		return nil, errors.New("can't find filename in user's keymap")
	}

	// fetch and decrypt filename's KeyStruct
	keyStructEncryptedJSON, ok := userlib.DatastoreGet(keyStructUUID)
	if !ok {
		return nil, errors.New("can't find keystruct in datastore")
	}
	keyStructDecryptedJSON, err := decrypt(keyStructKey, keyStructEncryptedJSON[64:], keyStructEncryptedJSON[:64])
	if err != nil {
		return nil, err
	}
	var filenameKeyStruct keyStruct
	err = json.Unmarshal(keyStructDecryptedJSON, &filenameKeyStruct)
	if err != nil {
		return nil, err
	}

	// fetch FileContent from Datastore
	fileContentEncryptedJSON, ok := userlib.DatastoreGet(filenameKeyStruct.FileUUID)
	if !ok {
		return nil, errors.New("can't find filecontent from datastore")
	}
	fileContentDecryptedJSON, err := decrypt(filenameKeyStruct.Key, fileContentEncryptedJSON[64:], fileContentEncryptedJSON[:64])
	if err != nil {
		return nil, err
	}
	var fileContent FileContent
	err = json.Unmarshal(fileContentDecryptedJSON, &fileContent)
	if err != nil {
		return nil, err
	}
	output := ""
	curBlockUUID := fileContent.LastBlock
	curBlockKey := fileContent.LastBlockKey
	for curBlockUUID != uuid.Nil {
		curBlockEncryptedJSON, ok := userlib.DatastoreGet(curBlockUUID)
		if !ok {
			return nil, errors.New("last block not found in datastore")
		}
		curBlockDecryptedJSON, err := decrypt(curBlockKey, curBlockEncryptedJSON[64:], curBlockEncryptedJSON[:64])
		if err != nil {
			return nil, err
		}
		var curBlock ContentBlock
		err = json.Unmarshal(curBlockDecryptedJSON, &curBlock)
		if err != nil {
			return nil, err
		}
		output = string(curBlock.ENContent) + output
		curBlockUUID = curBlock.PrevBlock
		curBlockKey = curBlock.PrevBlockKey
	}
	return []byte(output), nil

	// boilerplate code
	// storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	// if err != nil {
	// 	return nil, err
	// }
	// dataJSON, ok := userlib.DatastoreGet(storageKey)
	// if !ok {
	// 	return nil, errors.New(strings.ToTitle("file not found"))
	// }
	// err = json.Unmarshal(dataJSON, &content)
	// return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// check if filename in user's AccessControl
	ACUUID := userdata.AccessControlUUID
	ACenc, ok := userlib.DatastoreGet(ACUUID)
	if !ok {
		return uuid.Nil, errors.New("inviter's accesscontrol not found")
	}
	ACdec, err := decrypt(userdata.ACKey, ACenc[64:], ACenc[:64])
	if err != nil {
		return uuid.Nil, errors.New("can't decrypt inviter's accesscontrol")
	}
	var AC AccessControl
	err = json.Unmarshal(ACdec, &AC)
	if err != nil {
		return uuid.Nil, errors.New("can't unmarshal inviter's accesscontrol")
	}
	keyStructUUID, ok := AC.KeyStructUUIDMap[filename]
	if !ok {
		return uuid.Nil, errors.New("filename does not exist in inviter's ac.keystructuuidmap")
	}
	keyStructKey, ok := AC.KeyMap[filename]
	if !ok {
		return uuid.Nil, errors.New("filename does not exist in inviter's ac.keymap")
	}

	// check if recipient username in datastore
	hashedRecipientUsername := userlib.Hash([]byte(recipientUsername))[:16]
	recipientUUID := uuid.Must(uuid.FromBytes(hashedRecipientUsername))
	_, ok = userlib.DatastoreGet(recipientUUID)
	if !ok {
		return uuid.Nil, errors.New("recipient username not in datastore")
	}

	_, ok = AC.OwnedFiles[filename]
	caseNumber := 1
	if ok {
		caseNumber = 2
	}
	// type AccessControl struct { // this struct is encrypted
	// 	KeyStructUUIDMap    map[string]uuid.UUID // dictionary of pointers to keystruct (keys of maps == fileName)
	// 	KeyMap              map[string][]byte    // dictionary of keys used for encrypted keystruct
	// 	OwnedFiles          map[string]string    // see which files you own
	// 	InvitationNameMap   map[string][]string  //filename : username [case 2]
	// 	InvitationAccessMap map[string]uuid.UUID // filename-username : uuid of file [case 2]
	// 	InvitationKeyMap    map[string][]byte    //filename-username : key [case 2]
	// }

	// type keyStruct struct {
	// 	Key      []byte
	// 	FileUUID uuid.UUID
	// }

	// type InvitationBlock struct {
	// 	KeyStructUUID uuid.UUID
	// 	Key           []byte
	// }

	var invitation InvitationBlock
	// case 1: if inviter does not own the file that is being shared
	// just point to the existing keystruct that the inviter uses
	if caseNumber == 1 {
		invitation.KeyStructUUID = keyStructUUID
		invitation.Key = keyStructKey
	} else if caseNumber == 2 {
		// case 2: if inviter owns the file that is being shared
		// need to create a new keystruct for the invitee

		// fetch & decrypt the keystruct owned by the inviter, & store a duplicate keystruct with new key & UUID
		keyStructEncryptedJSON, ok := userlib.DatastoreGet(keyStructUUID)
		if !ok {
			return uuid.Nil, errors.New("can't find keystruct in datastore")
		}
		keyStructDecryptedJSON, err := decrypt(keyStructKey, keyStructEncryptedJSON[64:], keyStructEncryptedJSON[:64])
		if err != nil {
			return uuid.Nil, err
		}
		var filenameKeyStruct keyStruct
		err = json.Unmarshal(keyStructDecryptedJSON, &filenameKeyStruct)
		if err != nil {
			return uuid.Nil, err
		}
		newKeyStructUUID := uuid.New() //random uuid instead
		newKeyStructKey := userlib.RandomBytes(16)
		newKeyStruct := macandencrypt(newKeyStructKey, keyStructDecryptedJSON)
		userlib.DatastoreSet(newKeyStructUUID, newKeyStruct)
		invitation.KeyStructUUID = newKeyStructUUID
		invitation.Key = newKeyStructKey

		// adding the recipientusername to AC.InvitationNameMap, & the UUIDs/keys to the keystruct that we shared
		AC.InvitationNameMap[filename] = append(AC.InvitationNameMap[filename], recipientUsername)
		filenameusername := filename + recipientUsername
		AC.InvitationAccessMap[filenameusername] = newKeyStructUUID
		AC.InvitationKeyMap[filenameusername] = newKeyStructKey

		// store AC in datastore
		ACJSON, err := json.Marshal(AC)
		if err != nil {
			return uuid.Nil, err
		}
		ACEncrypted := macandencrypt(userdata.ACKey, ACJSON)
		userlib.DatastoreSet(ACUUID, ACEncrypted)
	}
	// marshal the invitation
	invitationJSON, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}
	invitationPtr = uuid.New()
	// userlib.KeystoreSet(username+" PKEEncKey", PKEEncKey)
	// userlib.KeystoreSet(username+" DSVerifyKey", DSVerifyKey)
	// encrypt with recipient's public key, sign with inviter's private key
	enckey, ok := userlib.KeystoreGet(recipientUsername + " PKEEncKey")
	if !ok {
		return uuid.Nil, errors.New("can't find recipient's PKEEncKey")
	}
	invitationEncrypted := signandencrypt(enckey, userdata.DSSignKey, invitationJSON)
	userlib.DatastoreSet(invitationPtr, invitationEncrypted)

	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// check if filename in user's AccessControl
	ACUUID := userdata.AccessControlUUID
	ACenc, ok := userlib.DatastoreGet(ACUUID)
	if !ok {
		return errors.New("invitee's accesscontrol not found")
	}
	ACdec, err := decrypt(userdata.ACKey, ACenc[64:], ACenc[:64])
	if err != nil {
		return err
	}
	var AC AccessControl
	err = json.Unmarshal(ACdec, &AC)
	if err != nil {
		return err
	}
	_, ok = AC.KeyStructUUIDMap[filename]
	if ok {
		return errors.New("filename exists in invitee's ac.keystructuuidmap, can't accept invitation")
	}

	// decrypt invitationPtr
	invitationEncrypted, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("can't find invitationptr in datastore")
	}
	// userlib.KeystoreSet(username+" PKEEncKey", PKEEncKey)
	// userlib.KeystoreSet(username+" DSVerifyKey", DSVerifyKey)
	// encrypt with recipient's public key, sign with inviter's private key
	deckey := userdata.PKEDecKey
	verifykey, ok := userlib.KeystoreGet(senderUsername + " DSVerifyKey")
	if !ok {
		return errors.New("can't find sender's public ds key in keystore")
	}
	invitationDecrypted, err := publicKeyDecrypt(deckey, verifykey, invitationEncrypted[256:], invitationEncrypted[:256])
	if err != nil {
		return err
	}
	var invitation InvitationBlock
	err = json.Unmarshal(invitationDecrypted, &invitation)
	if err != nil {
		return err
	}

	// check if invitation is still valid (i.e. keystruct still exists)
	_, ok = userlib.DatastoreGet(invitation.KeyStructUUID)
	if !ok {
		return errors.New("can't find keystruct of shared file in datastore")
	}

	// update invitee's AC to reflect the new UUID/key of the shared file's keystruct
	AC.KeyStructUUIDMap[filename] = invitation.KeyStructUUID
	AC.KeyMap[filename] = invitation.Key
	ACJSON, err := json.Marshal(AC)
	if err != nil {
		return err
	}
	ACEncrypted := macandencrypt(userdata.ACKey, ACJSON)
	userlib.DatastoreSet(ACUUID, ACEncrypted)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// fetch and decrypt user's AccessControl
	ACUUID := userdata.AccessControlUUID
	ACenc, ok := userlib.DatastoreGet(ACUUID)
	if !ok {
		return errors.New("not found")
	}
	ACdec, err := decrypt(userdata.ACKey, ACenc[64:], ACenc[:64])
	if err != nil {
		return errors.New("can't decrypt accesscontrol struct")
	}
	var AC AccessControl
	err = json.Unmarshal(ACdec, &AC)
	if err != nil {
		return errors.New("can't unmarshal accesscontrol struct")
	}
	keyStructUUID, ok := AC.KeyStructUUIDMap[filename]
	if !ok {
		return errors.New("can't find filename in user's keystructuuidmap")
	}
	keyStructKey, ok := AC.KeyMap[filename]
	if !ok {
		return errors.New("can't find filename in user's keymap")
	}

	// fetch and decrypt filename's KeyStruct
	keyStructEncryptedJSON, ok := userlib.DatastoreGet(keyStructUUID)
	if !ok {
		return errors.New("can't find keystruct in datastore")
	}
	keyStructDecryptedJSON, err := decrypt(keyStructKey, keyStructEncryptedJSON[64:], keyStructEncryptedJSON[:64])
	if err != nil {
		return err
	}
	var filenameKeyStruct keyStruct
	err = json.Unmarshal(keyStructDecryptedJSON, &filenameKeyStruct)
	if err != nil {
		return err
	}

	// fetch FileContent from Datastore
	fileContentEncryptedJSON, ok := userlib.DatastoreGet(filenameKeyStruct.FileUUID)
	if !ok {
		return errors.New("can't find filecontent from datastore")
	}
	fileContentDecryptedJSON, err := decrypt(filenameKeyStruct.Key, fileContentEncryptedJSON[64:], fileContentEncryptedJSON[:64])
	if err != nil {
		return err
	}

	newkey := userlib.RandomBytes(16)
	filecontentto := macandencrypt(newkey, fileContentDecryptedJSON)
	newfileuuid := uuid.New()
	userlib.DatastoreSet(newfileuuid, filecontentto)

	filenameKeyStruct.FileUUID = newfileuuid
	filenameKeyStruct.Key = newkey
	filenameKeystructenc, err := json.Marshal(filenameKeyStruct)
	if err != nil {
		return err
	}
	filenameKeyStructto := macandencrypt(keyStructKey, filenameKeystructenc)
	userlib.DatastoreSet(keyStructUUID, filenameKeyStructto)

	userlist := make([]string, 0, 0)
	for index, a := range AC.InvitationNameMap[filename] {
		// filenameusername := filename + a
		filenameusername := filename + a
		if a == recipientUsername {
			userlib.DatastoreDelete(AC.InvitationAccessMap[filenameusername])
			// userlib.DebugMsg(a)
		} else {
			userlist = append(userlist, a)
			print(index)
			dataenc, ok := userlib.DatastoreGet(AC.InvitationAccessMap[filenameusername])
			print(ok)
			data, err := decrypt(AC.InvitationKeyMap[filenameusername], dataenc[64:], dataenc[:64])
			if err != nil {
				return err
			}
			var keyStructUser keyStruct
			err = json.Unmarshal(data, &keyStructUser)
			if err != nil {
				return err
			}
			keyStructUser.FileUUID = newfileuuid
			keyStructUser.Key = newkey
			ksumarsh, err := json.Marshal(keyStructUser)
			if err != nil {
				return err
			}
			ksuto := macandencrypt(AC.InvitationKeyMap[filenameusername], ksumarsh)
			userlib.DatastoreSet(AC.InvitationAccessMap[filenameusername], ksuto)
		}
	}
	AC.InvitationNameMap[filename] = userlist
	ACmarsh, err := json.Marshal(AC)
	if err != nil {
		return err
	}
	ACto := macandencrypt(userdata.ACKey, ACmarsh)
	userlib.DatastoreSet(ACUUID, ACto)
	//revoke access
	return nil
}
