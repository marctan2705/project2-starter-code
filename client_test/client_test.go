package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	"strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

func measureBandwidth(probe func()) (bandwidth int) {
	before := userlib.DatastoreGetBandwidth()
	probe()
	after := userlib.DatastoreGetBandwidth()
	return after - before
 }
 


var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})



		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})
		Specify("Basic Test: Testing Unique Username Functionality", func() {
			userlib.DebugMsg("Inititalising Alice")
			alice, err = client.InitUser("Alice", "12345678")
			// print(alicedata)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("Alice", "12345678")
			// print(alicedata)
			Expect(err).ToNot(BeNil())
		})
		Specify("Basic Test: load file that doesnt exist", func() {
			userlib.DebugMsg("Inititalising Alice")
			alice, err = client.InitUser("Alice", "12345678")
			// print(alicedata)
			Expect(err).To(BeNil())
			filecontent, err := alice.LoadFile("file")
			Expect(filecontent).To(BeNil())
			Expect(err).ToNot(BeNil())
		})
		Specify("Basic Test: Testing Case Sensitive Functionality", func() {
			userlib.DebugMsg("Inititalising alice")
			alice, err = client.InitUser("alice", "12345678")
			// print(alicedata)
			Expect(err).To(BeNil())
			_, err := client.InitUser("Alice", "12345678")
			// print(Alicedata)
			Expect(err).To(BeNil())
			alicedatacheck, ok := userlib.DatastoreGet(uuid.Must(uuid.FromBytes(userlib.Hash([]byte("alice"))[:16])))
			print(alicedatacheck)
			Expect(ok).To(BeTrue())
			// Expect(alicedatacheck == alicedata).To(BeTrue())
		})
		Specify("Basic Test: Testing Non Unique Passwords Functionality", func() {
			userlib.DebugMsg("Inititalising alice")
			alicedata, err := client.InitUser("aaa", "12345678")
			print(alicedata)
			Expect(err).To(BeNil())
			Alicedata, err := client.InitUser("xxx", "12345678")
			print(Alicedata)
			Expect(err).To(BeNil())
			alicedatacheck, ok := userlib.DatastoreGet(uuid.Must(uuid.FromBytes(userlib.Hash([]byte("aaa"))[:16])))
			print(alicedatacheck)
			Expect(ok).To(BeTrue())
			// Expect(alicedatacheck == alicedata).To(BeTrue())
		})
		Specify("Basic Test: Testing Passwords Length Functionality", func() {
			userlib.DebugMsg("Inititalising alice")
			alicedata, err := client.InitUser("aaa", "")
			print(alicedata)
			Expect(err).To(BeNil())
			alicedatacheck, ok := userlib.DatastoreGet(uuid.Must(uuid.FromBytes(userlib.Hash([]byte("aaa"))[:16])))
			print(alicedatacheck)
			Expect(ok).To(BeTrue())
			// Expect(alicedatacheck == alicedata).To(BeTrue())
		})
		Specify("Basic Test: Testing Users With Same File Name Functionality", func() {
			userlib.DebugMsg("Inititalising alice")
			alicedata, err := client.InitUser("alice", "")
			print(alicedata)
			Expect(err).To(BeNil())
			alicedata.StoreFile("Wassup", []byte("cs170"))
			bobdata, err := client.InitUser("bob", "")
			print(alicedata)
			Expect(err).To(BeNil())
			bobdata.StoreFile("Wassup", []byte("cs161"))
			data, err := alicedata.LoadFile("Wassup")
			Expect(err).To(BeNil())
			Expect(string(data) == "cs170").To(BeTrue())
			datax, err := bobdata.LoadFile("Wassup")
			Expect(err).To(BeNil())
			Expect(string(datax) == "cs161").To(BeTrue())
			// Expect(alicedatacheck == alicedata).To(BeTrue())
		})
		Specify("Basic Test: Testing Users With Same File Name Functionality", func() {
			userlib.DebugMsg("Inititalising alice")
			alicedata, err := client.InitUser("alice", "")
			print(alicedata)
			Expect(err).To(BeNil())
			alicedata.StoreFile("Wassup", []byte("cs170"))
			data, err := alicedata.LoadFile("Wassup")
			Expect(err).To(BeNil())
			Expect(string(data) == "cs170").To(BeTrue())
			alicedata.StoreFile("Wassup", []byte("cs161"))
			data, err = alicedata.LoadFile("Wassup")
			Expect(err).To(BeNil())
			Expect(string(data) == "cs161").To(BeTrue())
			// Expect(alicedatacheck == alicedata).To(BeTrue())
		})
		Specify("Basic Test: Testing empty filename", func() {
			userlib.DebugMsg("Inititalising alice")
			alicedata, err := client.InitUser("alice", "")
			print(alicedata)
			Expect(err).To(BeNil())
			alicedata.StoreFile("", []byte("cs170"))
			data, err := alicedata.LoadFile("")
			Expect(err).To(BeNil())
			Expect(string(data) == "cs170").To(BeTrue())
			// Expect(alicedatacheck == alicedata).To(BeTrue())
		})

		Specify("Basic Test #3: Passwords need not be unique", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Bob.")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test #6: 3.6.2 Share a file with a user, and let the user overwrite the file", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Charles overwrites the file with an empty string.")
			err = charles.StoreFile(charlesFile, []byte(emptyString))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(emptyString)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(emptyString)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(emptyString)))
		})
		Specify("Basic Test #7: empty username", func() {
			userlib.DebugMsg("Initializing users \"\" ")
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
			Expect(alice).To(BeNil())
		})
		Specify("Basic Test #8: wrong username", func() {
			userlib.DebugMsg("Initializing Users Alice ")
			user, err := client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			Expect(user).ToNot(BeNil())
			userlib.DebugMsg("Attempting To Retrieve bob")
			user2, err := client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())
			Expect(user2).To(BeNil())
		})
		Specify("Basic Test #9: wrong password", func() {
			userlib.DebugMsg("Initializing Users Alice ")
			user, err := client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			Expect(user).ToNot(BeNil())
			userlib.DebugMsg("Attempting To Retrieve Alice")
			user2, err := client.GetUser("Alice", "kefbikbgruibf")
			Expect(err).ToNot(BeNil())
			Expect(user2).To(BeNil())
		})
		Specify("Basic Test #10: File Doesn't Exist", func() {
			userlib.DebugMsg("Initializing Users Alice ")
			user, err := client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			Expect(user).ToNot(BeNil())
			userlib.DebugMsg("Finding kukubird ")
			user.LoadFile("kukubird")
			Expect(err).To(BeNil())
		})
		Specify("Basic Test #10: If others can see if one revoked", func() {
			userlib.DebugMsg("Initializing Users Alice ")
			alice, err := client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			Expect(alice).ToNot(BeNil())
			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			Expect(bob).ToNot(BeNil())
			charles, err := client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			Expect(charles).ToNot(BeNil())
			err = alice.StoreFile("file", []byte(contentOne))
			Expect(err).To(BeNil())
			invite1, err := alice.CreateInvitation("file", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("Alice", invite1, "file")
			Expect(err).To(BeNil())
			invite2, err := alice.CreateInvitation("file", "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("Alice", invite2, "file")
			Expect(err).To(BeNil())
			err = alice.RevokeAccess("file", "charles")
			Expect(err).To(BeNil())
			filecontent, err := bob.LoadFile("file")
			Expect(err).To(BeNil())
			Expect(filecontent).To(Equal([]byte(contentOne)))

		})
		// Specify("Basic Test #11: Upload a ton of keys and it should still work", func() {
		// 	userlib.DebugMsg("Initializing Users Alice ")
		// 	alice, err := client.InitUser("Alice", defaultPassword)
		// 	Expect(err).To(BeNil())
		// 	Expect(alice).ToNot(BeNil())
		// 	userlib.DebugMsg("Store files ")
		// 	for i := 1; i < 1000; i++ {
		// 		// userlib.DebugMsg(strconv.Itoa(i))
		// 		alice.StoreFile(strconv.Itoa(i), []byte(strconv.Itoa(i)))
		// 	}
		// 	for j := 1; j < 1000; j++ {
		// 		// userlib.DebugMsg(strconv.Itoa(j))
		// 		data, err := alice.LoadFile(strconv.Itoa(j))
		// 		Expect(data).To(Equal([]byte(strconv.Itoa(j))))
		// 		Expect(err).To(BeNil())
		// 	}
		// })
		Specify("Basic Test #11: Upload a ton of keys and it should still work", func() {
			userlib.DebugMsg("Initializing Users Alice ")
			alice, err := client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			Expect(alice).ToNot(BeNil())
			alice.StoreFile("file", []byte("yo"))
			userlib.DebugMsg("Store files ")
			BW1 := measureBandwidth(func(){
			for i := 1; i < 500; i++ {
				// userlib.DebugMsg(strconv.Itoa(i))
				err = alice.AppendToFile("file", []byte("yo"))
				Expect(err).To(BeNil())
			}})
			BW2 := measureBandwidth(func(){
				for i := 1; i < 1000; i++ {
					// userlib.DebugMsg(strconv.Itoa(i))
					err = alice.AppendToFile("file", []byte("yo"))
					Expect(err).To(BeNil())
				}})
			BW3 := measureBandwidth(func(){
				for i := 1; i < 1500; i++ {
					// userlib.DebugMsg(strconv.Itoa(i))
					err = alice.AppendToFile("file", []byte("yo"))
					Expect(err).To(BeNil())
				}})
			Expect(BW2 - BW1 == BW3 - BW2).To(BeTrue())
			data, err := alice.LoadFile("file")
			print(data)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test #11: Upload a ton of keys and it should still work", func() {
			userlib.DebugMsg("Initializing Users Alice ")
			alice, err := client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			Expect(alice).ToNot(BeNil())
			alice.StoreFile("file", []byte("yo"))
			userlib.DebugMsg("Store files ")
			BW1 := measureBandwidth(func(){
			for i := 1; i < 3; i++ {
				// userlib.DebugMsg(strconv.Itoa(i))
				err = alice.StoreFile(strconv.Itoa(i), []byte("yo"))
				Expect(err).To(BeNil())
			}})
			BW2 := measureBandwidth(func(){
				for i := 3; i < 5; i++ {
					// userlib.DebugMsg(strconv.Itoa(i))
					err = alice.StoreFile(strconv.Itoa(i), []byte("yo"))
					Expect(err).To(BeNil())
				}})
			BW3 := measureBandwidth(func(){
				for i := 5; i < 7; i++ {
					// userlib.DebugMsg(strconv.Itoa(i))
					err = alice.StoreFile(strconv.Itoa(i), []byte("yo"))
					Expect(err).To(BeNil())
				}})
			// userlib.DebugMsg(strconv.Itoa(BW3 - BW2))
			// userlib.DebugMsg(strconv.Itoa(BW2 - BW1))
			Expect(BW2 - BW1 == BW3 - BW2).To(BeTrue())
			data, err := alice.LoadFile("file")
			print(data)
			Expect(err).To(BeNil())
		})

		Specify("Test: Changing FileContent and Keystruct, checking that LoadFile fails.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			dataStoreMap := userlib.DatastoreGetMap()
			UUIDsBeforeStore := make(map[userlib.UUID][]byte)
			for UUID, value := range dataStoreMap {
				UUIDsBeforeStore[UUID] = value
			}

			differences := make(map[userlib.UUID][]byte)

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			dataStoreMap = userlib.DatastoreGetMap()
			for UUID, value := range dataStoreMap {
				_, ok := UUIDsBeforeStore[UUID]
				if !ok {
					differences[UUID] = value
				}
			}

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			for UUID, value := range differences {
				userlib.DatastoreSet(UUID, append(value, value...))
			}

			userlib.DebugMsg("Loading file...")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Changing FileContent and Keystruct, checking that LoadFile fails.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			print(alice)
			alice2, err := client.GetUser("", "ewoifhiof")
			Expect(err).ToNot(BeNil())
			print(alice2)
		})

		Specify("Test: Inviting uncreated user throws error", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			print(alice)
			alice.StoreFile("file", []byte("rejhfehwrf"))
			testuuid, err := alice.CreateInvitation("file", "bob")
			Expect(err).ToNot(BeNil())
			Expect(testuuid).To(Equal(uuid.Nil))
		})

		Specify("Test: Trying to revoke uninvited user throws error", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			print(alice)
			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			print(bob)
			charles, err := client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			print(charles)
			alice.StoreFile("file", []byte("rejhfehwrf"))
			alice.CreateInvitation("file", "bob")
			err = alice.RevokeAccess("file", "charles")
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Trying to accept revoked invitiation throws error", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			print(alice)
			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			print(bob)
			alice.StoreFile("file", []byte("rejhfehwrf"))
			testuuid, err := alice.CreateInvitation("file", "bob")
			Expect(err).To(BeNil())
			Expect(testuuid).ToNot(Equal(uuid.Nil))
			err = alice.RevokeAccess("file", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", testuuid, "file2")
			Expect(err).ToNot(BeNil())
		})
		Specify("Test: Access from different log ins at once", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			print(alice)
			aliceLaptop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			print(aliceLaptop)
			aliceDesktop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			print(aliceDesktop)
			alice.StoreFile("file", []byte("rejhfehwrf"))
			// testuuid, err := alice.CreateInvitation("file", "bob")
			// Expect(err).To(BeNil())
			// Expect(testuuid).ToNot(Equal(uuid.Nil))
			content, err := alice.LoadFile("file")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("rejhfehwrf")))
			content2, err := aliceLaptop.LoadFile("file")
			Expect(err).To(BeNil())
			Expect(content2).To(Equal(content))
			content3, err := aliceDesktop.LoadFile("file")
			Expect(err).To(BeNil())
			Expect(content3).To(Equal(content))
		})
		Specify("Test: Non-owner cannot revoke access", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charles.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charlie, err := client.InitUser("charlie", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", "file", contentOne)
			err = alice.StoreFile("file", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation("file", "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", "file2")
			err = bob.AcceptInvitation("alice", invite, "file2")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charlie.")
			invite2, err := bob.CreateInvitation("file2", "charlie")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charlie accepting invite from Bob under filename %s.", "file3")
			err = charlie.AcceptInvitation("bob", invite2, "file3")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob revoking Charles's access from %s.", aliceFile)
			err = bob.RevokeAccess("file2", "charles")
			Expect(err).ToNot(BeNil())
		})

		Specify("Test: Cannot accept an invitation that is not yours", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charles.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", "file", contentOne)
			err = alice.StoreFile("file", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation("file", "bob")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, "file")
			Expect(err).ToNot(BeNil())

		})

		Specify("Test: Cannot accept an invitation if user wrong", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charles.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", "file", contentOne)
			err = alice.StoreFile("file", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation("file", "bob")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("charles", invite, "file")
			Expect(err).ToNot(BeNil())

		})

		Specify("Test: Cannot accept a invitation that is not there", func() {
			userlib.DebugMsg("Initializing users Alice, Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", "file", contentOne)
			err = alice.StoreFile("file", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation("file", "bob")
			Expect(err).To(BeNil())
			Expect(invite).ToNot(BeNil())
			err = bob.AcceptInvitation("bob", uuid.New(), "file")
			Expect(err).ToNot(BeNil())

		})

		Specify("Test: Revoked User Adversary: Revoke Bob, then try to access file directly", func() {
			userlib.DebugMsg("Initializing users Alice, Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", "file", contentOne)
			err = alice.StoreFile("file", []byte(contentOne))
			Expect(err).To(BeNil())

			dataStoreMap := userlib.DatastoreGetMap()
			UUIDsBeforeStore := make(map[userlib.UUID][]byte)
			for UUID, value := range dataStoreMap {
				UUIDsBeforeStore[UUID] = value
			}

			differences := make(map[userlib.UUID][]byte)

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation("file", "bob")
			Expect(err).To(BeNil())
			Expect(invite).ToNot(BeNil())

			dataStoreMap = userlib.DatastoreGetMap()
			for UUID, value := range dataStoreMap {
				_, ok := UUIDsBeforeStore[UUID]
				if !ok {
					differences[UUID] = value
				}
			}

			err = bob.AcceptInvitation("alice", invite, "file")
			Expect(err).To(BeNil())

			content, err := bob.LoadFile("file")
			userlib.DatastoreGetMap()
			Expect(err).To(BeNil())
			Expect(content).To(BeEquivalentTo([]byte(contentOne)))

			err = alice.RevokeAccess("file", "bob")
			Expect(err).To(BeNil())

			for UUID := range differences {
				_, ok := userlib.DatastoreGet(UUID)
				Expect(ok).To(BeFalse())
			}

		})

		Specify("Test: Check if append takes linear time wrt. size of append", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("file", []byte(contentOne))
			Expect(err).To(BeNil())

			beforeAppend := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile("file", []byte(contentOne))
			Expect(err).To(BeNil())
			afterAppend := userlib.DatastoreGetBandwidth()
			benchmark := afterAppend - beforeAppend

			for i := 0; i < 100; i++ {
				beforeAppend = userlib.DatastoreGetBandwidth()
				err = alice.AppendToFile("file", []byte(contentOne))
				Expect(err).To(BeNil())
				afterAppend = userlib.DatastoreGetBandwidth()
				bandwidth := afterAppend - beforeAppend
				Expect(bandwidth).To(Equal(benchmark))
			}
		})

		// Specify("Test: Access from different log ins at once", func() {
		// 	userlib.DebugMsg("Initializing user Alice.")
		// 	alice, err := client.InitUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())
		// 	print(alice)
		// 	aliceLaptop, err := client.GetUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())
		// 	print(aliceLaptop)
		// 	aliceDesktop, err := client.GetUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())
		// 	print(aliceDesktop)
		// 	alice.StoreFile("file", []byte("rejhfehwrf"))
		// 	// testuuid, err := alice.CreateInvitation("file", "bob")
		// 	// Expect(err).To(BeNil())
		// 	// Expect(testuuid).ToNot(Equal(uuid.Nil))
		// 	content, err := alice.LoadFile("file")
		// 	Expect(err).To(BeNil())
		// 	Expect(content).To(Equal([]byte("rejhfehwrf")))
		// 	content2, err := aliceLaptop.LoadFile("file")
		// 	Expect(err).To(BeNil())
		// 	Expect(content2).To(Equal(content))
		// 	content3, err := aliceDesktop.LoadFile("file")
		// 	Expect(err).To(BeNil())
		// 	Expect(content3).To(Equal(content))
		// })

		// Specify("Test: Check number of keys in keystore is O(n), n = number of users", func() {
		// 	userlib.DebugMsg("Initializing user Alice.")
		// 	alice, err = client.InitUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())
		// 	numberOfKeysPerUser := len(userlib.KeystoreGetMap())
		// 	numUsers := 1
		// 	for i := 1; i < 100; i++ {
		// 		// userlib.DebugMsg(strconv.Itoa(i))
		// 		alice.StoreFile(strconv.Itoa(i), []byte(strconv.Itoa(i)))
		// 	}

		// 	numberOfKeys := len(userlib.KeystoreGetMap())
		// 	userlib.DebugMsg("Check if number of files don't change number of keys")
		// 	Expect(numberOfKeys).To(BeIdenticalTo(numberOfKeysPerUser))

		// 	for i := 1; i < 100; i++ {
		// 		client.InitUser(strconv.Itoa(i), defaultPassword)
		// 		numUsers += 1
		// 	}
		// 	numberOfKeys = len(userlib.KeystoreGetMap())
		// 	userlib.DebugMsg("Check if number of users linearly scale with number of keys")
		// 	Expect(numberOfKeys).To(BeIdenticalTo(numberOfKeysPerUser * numUsers))

		// 	for i := 1; i < 100; i++ {
		// 		invitationPtr, err := alice.CreateInvitation("1", strconv.Itoa(i))
		// 		Expect(err).To(BeNil())
		// 		user, err := client.GetUser(strconv.Itoa(i), defaultPassword)
		// 		Expect(err).To(BeNil())
		// 		err = user.AcceptInvitation("alice", invitationPtr, "1")
		// 		Expect(err).To(BeNil())
		// 	}

		// 	userlib.DebugMsg("Check if number of shares don't change number of keys")
		// 	numberOfKeys = len(userlib.KeystoreGetMap())
		// 	Expect(numberOfKeys).To(BeIdenticalTo(numberOfKeysPerUser * numUsers))

		// 	massiveContent := " "
		// 	i := 0
		// 	for i < 1000 {
		// 		massiveContent += "A"
		// 		i += 1
		// 	}

		// 	err = alice.AppendToFile("1", []byte(massiveContent))
		// 	Expect(err).To(BeNil())

		// 	numberOfKeys = len(userlib.KeystoreGetMap())
		// 	userlib.DebugMsg("Check if filesize doesn't change number of keys")
		// 	Expect(numberOfKeys).To(BeIdenticalTo(numberOfKeysPerUser * numUsers))
		// })
		///////////////////////////////////////////////////////////////////////////////////////////

		// Specify("Basic Test #10: Integrity compromised", func() {
		// 	userlib.DebugMsg("Initializing Users Alice ")
		// 	user, err := client.InitUser("Alice", defaultPassword)
		// 	Expect(err).To(BeNil())
		// 	Expect(user).ToNot(BeNil())
		// 	userlib.DebugMsg("Making kkb ")
		// 	user.StoreFile("kkb", []byte("rawr"))
		// 	Expect(err).To(BeNil())
		// 	for UUID := range userlib.DatastoreGetMap() {
		// 		userlib.DatastoreSet(UUID, []byte("yoyoy"))
		// 	}
		// 	userlib.DebugMsg("Get kkb ")
		// 	user.LoadFile("kkb")
		// 	Expect(err).ToNot(BeNil())

		// })

		// changing Alice's userstruct
		// dataStoreMap := userlib.DatastoreGetMap()
		// for UUID, value := range dataStoreMap {
		// 	userlib.DatastoreSet(UUID, append(value, value...))
		// }

		// 	userlib.DebugMsg("Getting user Alice.")
		// 	aliceLaptop, err = client.GetUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	// changing Alice's userstruct
		// 	dataStoreMap := userlib.DatastoreGetMap()
		// 	for UUID := range dataStoreMap {
		// 		userlib.DatastoreSet(UUID, []byte(emptyString))
		// 	}

		// 	userlib.DebugMsg("Getting user Alice on laptop after editing all user structs (Should return error).")
		// 	aliceLaptop, err = client.GetUser("alice", defaultPassword)
		// 	Expect(err).ToNot(BeNil())

		// 	userlib.DebugMsg("Getting user Alice after editing all user structs (Should return error).")
		// 	alice, err = client.GetUser("alice", defaultPassword)
		// 	Expect(err).ToNot(BeNil())
		// })

		Specify("Basic Test: Tampering with User.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			dataStoreMap := userlib.DatastoreGetMap()
			for UUID := range dataStoreMap {
				userlib.DatastoreSet(UUID, []byte("eve's malicious data"))
			}
			aliceupdated, err :=client.GetUser("alice", defaultPassword)
			Expect(aliceupdated).To(BeNil())
			Expect(err).ToNot(BeNil())
		})
		Specify("Basic Test: Revoke cannot append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initialise user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("file", []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation("file", "bob")
			Expect(err).To(BeNil())
			Expect(invite).ToNot(BeNil())
			err = alice.RevokeAccess("file", "bob")
			Expect(err).To(BeNil())
			err = bob.AppendToFile("file", []byte(contentOne))
			Expect(err).ToNot(BeNil())

		})
		

	})
})
