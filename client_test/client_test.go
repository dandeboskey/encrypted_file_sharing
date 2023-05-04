package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
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

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
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
	dorisFile := "dorisFile.txt"
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

		Specify("Custom Test: Case Sensitive Users", func() {
			userlib.DebugMsg("Initializing users Alice, and alice")
			bob, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			bob, err = client.GetUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Custom Test: Testing Revoke w/ Full Tree and Multiple Appends", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Charlie, and Doris.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Doris for file %s, and Doris accepting invite under name %s.", aliceFile, dorisFile)
			invite, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Doris can load the file.")
			data, err = doris.LoadFile(dorisFile)
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

			userlib.DebugMsg("Alice revoking Doris's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Doris lost access to the file.")
			_, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Doris cannot append to the file.")
			err = doris.AppendToFile(dorisFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Charles can append to the file.")
			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can append to the file.")
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that appends succeeded for Alice, Bob, and Charles")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Doris lost access to the file.")
			_, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing Empty Usernames", func() {
			userlib.DebugMsg("Initializing user")
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing Empty Password", func() {
			userlib.DebugMsg("Initializing user alice")
			alice, err = client.InitUser("alice", "")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting user alice.")
			alice, err = client.GetUser("alice", "")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing Unique Usernames", func() {
			userlib.DebugMsg("Initializing user alice")
			alice, err = client.InitUser("alice", "a")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice.")
			alice, err = client.GetUser("alice", "a")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user alice")
			alice, err = client.InitUser("alice", "a")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Loggin in with Incorrect Password", func() {
			userlib.DebugMsg("Initializing user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice.")
			alice, err = client.GetUser("alice", "sdf")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Grandchild Revoke", func() {
			userlib.DebugMsg("Initializing user alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice Invite Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", aliceFile)
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob Invite Charles")
			invite, err = bob.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting invite from Bob under filename %s.", aliceFile)
			err = charles.AcceptInvitation("bob", invite, aliceFile)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles Invite Doris")
			invite, err = bob.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice Revoke Access to Bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob can't load file")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob can't append")
			err = bob.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob can't Invite Charles")
			invite, err = bob.CreateInvitation(aliceFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles can't load file")
			_, err = charles.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles can't append")
			err = charles.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles can't Invite Doris")
			invite, err = charles.CreateInvitation(aliceFile, "doris")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Doris can't accept invite")
			err = doris.AcceptInvitation("charles", invite, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: duplicate users", func() {
			userlib.DebugMsg("init alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("init alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: get w/o init", func() {
			userlib.DebugMsg("init alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: store empty file", func() {
			userlib.DebugMsg("init alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing empty file")
			err = alice.StoreFile(aliceFile, []byte{})
			Expect(err).To(BeNil())

			_, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
		})

		Specify("Custom test: should support case-sensitive usernames", func() {
			alice1, err1 := client.InitUser("alice", defaultPassword)
			Expect(err1).To(BeNil())
	
			alice2, err2 := client.InitUser("Alice", defaultPassword)
			Expect(err2).To(BeNil())
	
			Expect(alice1).ToNot(Equal(alice2))
		}) 

		Specify("should support multiple users", func() {
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			_, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			_, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("should support any length > 0 usernames", func() {
			_, err := client.InitUser("a", defaultPassword)
			Expect(err).To(BeNil())

			_, err = client.InitUser("aslkdjflsdjfl;jasdl;jfasldkjflskdjjfksdjfkdjkfjkjeidk", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("should not support empty usernames", func() {
			_, err := client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("should support any length > 0 passwords", func() {
			_, err := client.InitUser("alice", "g")
			Expect(err).To(BeNil())

			_, err = client.InitUser("alice2", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz")
			Expect(err).To(BeNil())
		})

		Specify("should not support empty passwords", func() {
			_, err := client.InitUser("alice", "")
			Expect(err).ToNot(BeNil())
		})

		Specify("should allow duplicate passwords", func() {
			_, err := client.InitUser("alice", "password")
			Expect(err).To(BeNil())

			_, err = client.InitUser("bob", "password")
			Expect(err).To(BeNil())
		})


		Specify("should replace file content", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
	
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
	
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
	
			content, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentTwo)))
		})
	
		Specify("should replace file content after append", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
	
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
	
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
	
			content, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne + contentTwo)))
	
			err = alice.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())
	
			content, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentThree)))
		})
	
		Specify("should allow duplicate file names for different users", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
	
			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
	
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
	
			err = bob.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
		})

		Specify("Overwrite doesn’t break sharing", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err := client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
	
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
	
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
	
			err = bob.AcceptInvitation("alice", invitationPtr, bobFile)
			Expect(err).To(BeNil())
	
			invitationPtr, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
	
			err = charles.AcceptInvitation("bob", invitationPtr, charlesFile)
			Expect(err).To(BeNil())
	
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
	
			content, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentTwo)))
	
			content, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentTwo)))
	
			err = bob.StoreFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())
	
			content, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentThree)))
	
			content, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentThree)))
	
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
	
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())
	
			err = charles.AppendToFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())
	
			content, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentThree + contentOne + contentTwo + contentThree)))
	
			content, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentThree + contentOne + contentTwo + contentThree)))
	
			content, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentThree + contentOne + contentTwo + contentThree)))
	
			david, err := client.InitUser("david", defaultPassword)
			Expect(err).To(BeNil())
	
			invitationPtr, err = charles.CreateInvitation(charlesFile, "david")
			Expect(err).To(BeNil())
	
			err = david.AcceptInvitation("charles", invitationPtr, "davidFile")
			Expect(err).To(BeNil())
	
			content, err = david.LoadFile("davidFile")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentThree + contentOne + contentTwo + contentThree)))
		})

		Specify("Nonexistent File", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			_, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		
			_, err = alice.CreateInvitation("nonexistentFile", "bob")
			Expect(err).NotTo(BeNil())
		})
		
		Specify("Nonexistent Recipient", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
		
			_, err = alice.CreateInvitation(aliceFile, "nonexistentBob")
			Expect(err).NotTo(BeNil())
		})
		
		Specify("Nonexistent Both", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		
			_, err = alice.CreateInvitation("nonexistentFile", "nonexistentBob")
			Expect(err).NotTo(BeNil())
		})

		Specify("Custom Test: sharing permissions", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err := client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invitationPtr, "bobFile")
			Expect(err).To(BeNil())

			content, err := bob.LoadFile("bobFile")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne)))

			err = bob.StoreFile("bobFile", []byte(contentTwo))
			Expect(err).To(BeNil())

			content, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentTwo)))

			err = bob.AppendToFile("bobFile", []byte(contentThree))
			Expect(err).To(BeNil())

			content, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentTwo + contentThree)))

			invitationPtr, err = bob.CreateInvitation("bobFile", "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invitationPtr, "charlesFile")
			Expect(err).To(BeNil())

			content, err = charles.LoadFile("charlesFile")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentTwo + contentThree)))

			err = charles.StoreFile("charlesFile", []byte(contentOne))
			Expect(err).To(BeNil())

			content, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne)))

			content, err = bob.LoadFile("bobFile")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne)))

			err = charles.AppendToFile("charlesFile", []byte(contentTwo))
			Expect(err).To(BeNil())

			content, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne + contentTwo)))

			content, err = bob.LoadFile("bobFile")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne + contentTwo)))
		})

		Specify("Nonexistent File", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			_, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})
		
		Specify("Nonexistent Recipient", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
		
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})
		
		Specify("Never shared with Recipient", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			_, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
		
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		/** Specify("Shared then revoked then revoked invite never accepted", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			_, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
		
			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
		
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		}) */
		
		Specify("Shared and accepted then revoked then revoked", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
		
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
		
			err = bob.AcceptInvitation("alice", invitationPtr, bobFile)
			Expect(err).To(BeNil())
		
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
		
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Malicious Adversary Invites", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
		
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
		
			userlib.DatastoreDelete(invitationPtr)
			err = bob.AcceptInvitation("alice", invitationPtr, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Incorrect Invite Sequence", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err := client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			invitationPtr2, err := bob.CreateInvitation(aliceFile, "charles")
			Expect(err).ToNot(BeNil())
			err = charles.AcceptInvitation("bob", invitationPtr2, charlesFile)
			Expect(err).ToNot(BeNil())
			err = bob.AcceptInvitation("alice", invitationPtr, bobFile)
			Expect(err).To(BeNil())
		})

		Specify("User DNE", func() {
			_, err := client.GetUser("alice", defaultPassword)
			Expect(err).NotTo(BeNil())
		})
		
		Specify("Invalid credentials", func() {
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		
			_, err = client.GetUser("alice", "passward")
			Expect(err).NotTo(BeNil())
		})
		
		Specify("Invalid credentials, empty password", func() {
			_, err := client.GetUser("alice", emptyString)
			Expect(err).NotTo(BeNil())
		})
		
		Specify("Multiple sessions get", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		
			aliceLaptop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		
			aliceDesktop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		
			alicePhone, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			content, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne)))
		
			content, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne)))
		
			content, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne)))
		
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
		
			content, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne + contentTwo)))
		
			content, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne + contentTwo)))
		})

		Specify("Custom Test: ", func() {
			
		})
	})
})
