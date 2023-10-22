package client

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

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username  string
	userkey   []byte
	DSSignKey userlib.DSSignKey
	PKEDecKey userlib.PKEDecKey
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username
	
	// Step 1: Use password and salt to generate a user key.
	var userkey []byte
	userkey = userlib.Argon2Key([]byte(password), []byte(username), 16)
	userdata.userkey = userkey

	// Step 2: Generate key pairs for encryption (PKEKeyGen() -> PKEEncKey, PKEDecKey).maybe for file later
	var PKEEncKey userlib.PKEEncKey
	var PKEDecKey userlib.PKEDecKey
	PKEEncKey, PKEDecKey, _ = userlib.PKEKeyGen()
	userdata.PKEDecKey = PKEDecKey

	// Step 3: Generate key pairs for signature (DSKeyGen() -> DSSignKey, DSVerifyKey).
	var DSSignKey userlib.DSSignKey
	var DSVerifyKey userlib.DSVerifyKey
	DSSignKey, DSVerifyKey, _ = userlib.DSKeyGen()
	userdata.DSSignKey = DSSignKey

	// Step 4: Convert the user struct to bytes (json.Marshal(User data type) -> bytes).
	userdataBytes, err := json.Marshal(userdata)

	// Step 5: Use PKEEnc function to encrypt it to get ciphertext (PKEEnc(ek PKEEncKey, plaintext) -> ciphertext).
	iv := userlib.RandomBytes(16)
	ciphertext := userlib.SymEnc(userkey, iv, userdataBytes)

	// Step 6: Sign the ciphertext (DSSign(DSSignKey, msg) -> sig).
	sig, _ := userlib.DSSign(DSSignKey, ciphertext)

	// Step 7: Generate a UUID using sig and store (UUID, sig) in the datastore.
	sigUUID, err := uuid.FromBytes(userlib.Argon2Key(userkey, []byte("sig"), 16))
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(sigUUID, sig)

	// Step 8: Generate a UUID using the ciphertext and store (UUID, ciphertext) in the datastore.
	ciphertextUUID, err := uuid.FromBytes(userlib.Argon2Key(userkey, []byte("ciphertext"), 16))
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(ciphertextUUID, ciphertext)

	// Step 9: Store (UsernameDSVerifyKey, DSVerifyKey) in the keystore (for verifying the signature).
	err = userlib.KeystoreSet(username+"DSVerifyKey", DSVerifyKey)
	if err != nil {
		return nil, err
	}

	//Step 10 Store PKEDecKey in keystore.for later
	err = userlib.KeystoreSet(username+"PKEEncKey", PKEEncKey)
	if err != nil {
		return nil, err
	}
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	// Step 1: Use the given username and password to retrieve the userkey.
	userkey := userlib.Argon2Key([]byte(password), []byte(username), 16)

	// Step 2: Use the user key to retrieve UUID for sig and ciphertext.
	sigUUID, err := uuid.FromBytes(userlib.Argon2Key(userkey, []byte("sig"), 16))
	if err != nil {
		return nil, err
	}
	ciphertextUUID, err := uuid.FromBytes(userlib.Argon2Key(userkey, []byte("ciphertext"), 16))
	if err != nil {
		return nil, err
	}

	// Step 3: Get (UUID, sig), (UUID, ciphertext) from the datastore.
	sig, ok := userlib.DatastoreGet(sigUUID)
	if ok == false {
		return nil, errors.New("Signature not found")
	}
	ciphertext, ok := userlib.DatastoreGet(ciphertextUUID)
	if ok == false {
		return nil, errors.New("Ciphertext not found")
	}
	// Step 4: Get (UsernameDSVerifyKey, DSVerifyKey), (usernameEnc-PKEDecKey, Enc-PKEDecKey) from keystore.
	DSVerifyKey, ok := userlib.KeystoreGet(username + "DSVerifyKey")
	if ok == false {
		return nil, errors.New("dsverifykey not found")
	}

	// Step 5: Verify that the ciphertext was not changed (DSVerify(DSVerifyKey, ciphertext, sig)).
	err = userlib.DSVerify(DSVerifyKey, ciphertext, sig)
	if err != nil {
		return nil, errors.New("Signature Verification Failed")
	}

	// Step 6: Use the EncPKEDecKey for decryption of the ciphertext.
	plaintext := userlib.SymDec(userkey, ciphertext)

	// Step 7: Convert to UserType.
	var userData User
	err = json.Unmarshal(plaintext, &userData)
	if err != nil {
		return nil, err
	}

	// Step 8: Check if username matched.
	if userData.Username != username {
		return nil, errors.New("Username Doesn't match")
	}

	return userdataptr, nil
}

// Helper function Enc-Then-HMac
func EncryptAndHMAC(encKey []byte, data interface{}) (ciphertext []byte, hmac []byte, err error) {
	// Convert data to bytes using JSON encoding
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, nil, err
	}

	// Generate a random IV (Initialization Vector) for symmetric encryption
	iv := userlib.RandomBytes(16)

	// Encrypt the data using symmetric encryption
	encryptedData := userlib.SymEnc(encKey, iv, dataBytes)

	// Compute the HMAC for integrity verification using the encryption key as HMAC key
	hmac, err = userlib.HMACEval(encKey, encryptedData)
	if err != nil {
		return nil, nil, err
	}

	return encryptedData, hmac, nil
}

// Helper function Enc-Then-Sign
func EncryptAndSign(signKey userlib.DSSignKey, encKey []byte, data interface{}) (ciphertext []byte, sig []byte, err error) {
	// Convert data to bytes using JSON encoding
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, nil, err
	}

	// Generate a random IV (Initialization Vector) for symmetric encryption
	iv := userlib.RandomBytes(16)

	// Encrypt the data using symmetric encryption
	encryptedData := userlib.SymEnc(encKey, iv, dataBytes)

	// Sign the ciphertext using digital signature
	sig, err = userlib.DSSign(signKey, encryptedData)
	if err != nil {
		return nil, nil, err
	}

	return encryptedData, sig, nil
}

// Helper function HMac-then-Decryption
func HMACAndDecrypt(decKey []byte, ciphertext, hmac []byte, data interface{}) (err error) {
	// Verify the integrity of the ciphertext using the HMAC tag
	verify_hmac, err := userlib.HMACEval(decKey, ciphertext)
	if !userlib.HMACEqual(verify_hmac, hmac) {
		return errors.New("HMAC verification failed, data may have been tampered with")
	}

	// Decrypt the ciphertext using symmetric decryption
	decryptedData := userlib.SymDec(decKey, ciphertext)

	// Convert the decrypted bytes back to the original data type using JSON decoding
	err = json.Unmarshal(decryptedData, &data)
	if err != nil {
		return
	}

	return nil
}

// Helper function Verify-Then-Decryption
func VerifyAndDecrypt(verifyKey userlib.DSVerifyKey, decKey []byte, ciphertext, sig []byte, data interface{}) (err error) {
	// Verify the signature of the ciphertext using digital signature
	err = userlib.DSVerify(verifyKey, ciphertext, sig)
	if err != nil {
		return errors.New("Signature verification failed, data may have been tampered with")
	}

	// Decrypt the ciphertext using symmetric decryption
	decryptedData := userlib.SymDec(decKey, ciphertext)

	// Convert the decrypted bytes back to the original data type using JSON decoding
	err = json.Unmarshal(decryptedData, &data)
	if err != nil {
		return
	}

	return nil
}

func uuidAndStringToFromBytesUUID(uuidINPUT uuid.UUID, str string) (UUID_Bytes uuid.UUID, err error) {
	bytes := append(uuidINPUT[:], []byte(str)...)[:16]
	UUID_Bytes, err = uuid.FromBytes(bytes) // Fixed this line to use append()

	if err != nil {
		print("Error getting uuid from bytes")
		return uuid.Nil, err
	}

	return UUID_Bytes, nil
}

// STORES FILE META DATA
// UUID IS RANDOM
type FileInfo struct {
	Owner                    string
	Start_file_contents_UUID uuid.UUID
	Next_file_contents_UUID  uuid.UUID
	Key_for_contents         []byte
}

// STORES THE POINTER TO FILE DATA, EITHER FILEINFO OR INVITATION
// UUID IS PBKDF OF USERNAME + FILENAME
type FileName struct {
	Owner        string
	File_pointer uuid.UUID
	Invitations  []string
}

// STORES THE CONTENTS OF FILE AND NEXT FILECONTENTS POINTER
// UUID IS RANDOM
type FileContent struct {
	Contents                []byte
	Next_file_contents_UUID uuid.UUID
}

// STORES POINTER TO FILEINFO, OTHER INVITATIONS GIVEN BY THIS INTENDED USER, OWNER, AND INTENDED USER
// UUID IS RANDOM
type Invitation struct {
	Owner                 string
	FileInfo_UUID         uuid.UUID
	Receiver              string // The username of the receiver (who receives the invitation)
	dec_decFileContentKey userlib.PKEDecKey
	original_filename     string
}

// New struct to represent the access granted to a user for a file
type Access struct {
	FileInfoUID uuid.UUID // The UUID of the FileInfo struct
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	// step 1 - use username and filename to generate the UUID for FileName struct
	var username string = userdata.Username
	fileNameUUIDBytes := userlib.Argon2Key([]byte(username), []byte(filename), 16) // 16 bytes
	fileNameUUID, err := uuid.FromBytes(fileNameUUIDBytes)
	if err != nil {
		return errors.New("Error generating UUID for FileName UUID")
	}

	// fileName_HMAC_UUID, err := uuid.FromBytes(append(fileNameUUIDBytes, []byte("HMAChmac")...))
	fileName_HMAC_UUID, err := uuidAndStringToFromBytesUUID(fileNameUUID, "HMAChmac")
	if err != nil {
		return errors.New("Error generating UUID for FileName HMAC UUID")
	}

	// step 2 - check datastore to see if that filename already exists in the userspace
	fileNameBytes, ok := userlib.DatastoreGet(fileNameUUID)

	// step 3 - if filename not created yet, need to create
	if ok == false {
		// create fileInfo struct that will be stored
		var newFileInfo FileInfo
		// generate UUID for fileInfo
		newFileInfo_UUID := uuid.New()
		newFileInfo_Sig_UUID, err := uuidAndStringToFromBytesUUID(newFileInfo_UUID, "Signature")

		// generate key for file contents, use filename + "FileContent" as salt
		FileContentKey, err := userlib.HashKDF(userdata.userkey, []byte(filename+"FileContent"))
		if err != nil {
			return errors.New("Error generating key for file contents")
		}
		// slice to 16 bytes
		FileContentKey = FileContentKey[:16]

		// set owner
		newFileInfo.Owner = username
		newFileInfo.Key_for_contents = FileContentKey
		// generate UUIDS for the filecontents
		startFC_UUID := uuid.New()

		// startFC_HMAC_UUID, err := uuid.FromBytes(append(startFC_UUID.Bytes(), []byte("HMAChmac")...))
		startFC_HMAC_UUID, err := uuidAndStringToFromBytesUUID(startFC_UUID, "HMAChmac")
		if err != nil {
			return errors.New("Error generating UUID for start FC HMAC struct")
		}

		nextFC_UUID := uuid.New()
		nextFC_HMAC_UUID, err := uuidAndStringToFromBytesUUID(nextFC_UUID, "HMAChmac")
		if err != nil {
			return errors.New("Error generating UUID for next FC HMAC struct")
		}
		// set the UUIDs
		newFileInfo.Start_file_contents_UUID = startFC_UUID
		newFileInfo.Next_file_contents_UUID = nextFC_UUID
		// generate a key for FileInfo Encryption
		FileInfo_Encryption_Key := userlib.Argon2Key(userdata.userkey, []byte(filename+"FileInfo"), 16)
		// FileInfo Encryption
		newFileInfo_Ciphertext, newFileInfo_Sig, err := EncryptAndSign(userdata.DSSignKey, FileInfo_Encryption_Key, newFileInfo)

		// NOW NEED TO CREATE NEW FILE CONTENT STRUCTS, uuid is startFC_UUID
		var newFileContent FileContent
		var nextFileContent FileContent
		newFileContent.Contents = content
		nextFileContent.Contents = nil

		// set next pointer to nextFC
		newFileContent.Next_file_contents_UUID = nextFC_UUID

		// SET next pointer to uuid.Nil
		nextFileContent.Next_file_contents_UUID = uuid.Nil

		// encrypt file content and nextfile Content
		newFileContent_Ciphertext, newFileContent_HMAC, err := EncryptAndHMAC(FileContentKey, newFileContent)
		nextFileContent_Ciphertext, nextFileContent_HMAC, err := EncryptAndHMAC(FileContentKey, nextFileContent)

		// create new FileName struct for user
		var userFileName FileName
		// set pointer to newFileInfo UUID
		userFileName.File_pointer = newFileInfo_UUID
		userFileName.Owner = username
		// encrypt FileName
		FileName_Encryption_Key := userlib.Argon2Key(userdata.userkey, []byte(filename+"FileName"), 16)
		userFileName_Ciphertext, userFileName_HMAC, err := EncryptAndHMAC(FileName_Encryption_Key, userFileName)

		// upload fileName
		userlib.DatastoreSet(fileNameUUID, userFileName_Ciphertext)
		userlib.DatastoreSet(fileName_HMAC_UUID, userFileName_HMAC)
		// upload file content
		userlib.DatastoreSet(startFC_UUID, newFileContent_Ciphertext)
		userlib.DatastoreSet(startFC_HMAC_UUID, newFileContent_HMAC)
		// upload next file content
		userlib.DatastoreSet(nextFC_UUID, nextFileContent_Ciphertext)
		userlib.DatastoreSet(nextFC_HMAC_UUID, nextFileContent_HMAC)
		// upload file info
		userlib.DatastoreSet(newFileInfo_UUID, newFileInfo_Ciphertext)
		userlib.DatastoreSet(newFileInfo_Sig_UUID, newFileInfo_Sig)

	} else {
		// If filename was created
		// unmarshal filenamestruct
		var userFN_value FileName
		fileNameBytesHMAC, ok := userlib.DatastoreGet(fileName_HMAC_UUID)

		// encrypt FileName
		FileName_Encryption_Key := userlib.Argon2Key(userdata.userkey, []byte(filename+"FileName"), 16)

		err = HMACAndDecrypt(FileName_Encryption_Key, fileNameBytes, fileNameBytesHMAC, &userFN_value)
		if err != nil {
			return errors.New("Error decrypting FileName struct")
		}

		// get pointer to fileInfo and get fileInfo / invitation
		userFileBytes, ok := userlib.DatastoreGet(userFN_value.File_pointer)
		if ok == false {
			return errors.New("FileInfo struct not found")
		}

		userFI_UUID := userFN_value.File_pointer

		// get bytes, check for error
		UFBYTESTEMP, err := uuidAndStringToFromBytesUUID(userFN_value.File_pointer, "Signature")
		if err != nil {
			return errors.New("Error generating UUID for FileInfo struct")
		}
		userFile_Sig, ok := userlib.DatastoreGet(UFBYTESTEMP)
		if ok == false {
			return errors.New("FileInfo signature not found")
		}

		// first try fileInfo, then try invitation
		var userFI FileInfo
		var userInv Invitation

		//InvitationHMAC
		whichType := 0

		//get verifykey
		DSVerifyKey, ok := userlib.KeystoreGet(username + "DSVerifyKey")

		//get decrypt key
		FileInfo_Dec_Key := userlib.Argon2Key(userdata.userkey, []byte(filename+"FileInfo"), 16)
		// errors if not a valid fileInfo struct
		error1 := VerifyAndDecrypt(DSVerifyKey, FileInfo_Dec_Key, userFileBytes, userFile_Sig, &userFI)
		if error1 != nil {
			...
		} else {
			...
		}

		// if this is an invitation, need to check if the user is the intended user
		if whichType == 2 {
			// if the user is not the intended user, return error
			//Chris: Is there need to check with invitations list name with the user name? It seems to return true all the time.
			if userInv.Receiver != username {
				return errors.New("User is not the intended user")
			}
			// need to get the fileinfo struct from the fileinfo UUID in the invitation
			fileInfoBytes, ok := userlib.DatastoreGet(userInv.FileInfo_UUID)
			if ok == false {
				return err
			}
			// unmarshal the fileinfo struct
			err := json.Unmarshal(fileInfoBytes, &userFI)
			if err != nil {
				return err
			}
		}
		...
		//Get file content and renew content.
		var filecontent FileContent
		filecontent_cipher, ok := userlib.DatastoreGet(userFI.Start_file_contents_UUID)
		if ok == false {
			return errors.New("File START not found")
		}

		// filecontent_HMAC_UUID, err := uuid.FromBytes(append((userFI.Start_file_contents_UUID).Bytes(), []byte("HMAChmac")...))
		filecontent_HMAC_UUID, err := uuidAndStringToFromBytesUUID(userFI.Start_file_contents_UUID, "HMAChmac")
		if err != nil {
			return errors.New("Error generating UUID for start FC HMAC struct")
		}
		filecontent_HMAC, ok := userlib.DatastoreGet(filecontent_HMAC_UUID)
		if ok == false {
			return errors.New("File START HMAC not found")
		}

		//Get Decryption key
		FileContent_Dec_Key, err := userlib.PKEDec(userdata.PKEDecKey, userFI.Key_for_contents)

		//decrypt
		err = HMACAndDecrypt(FileContent_Dec_Key, filecontent_cipher, filecontent_HMAC, &filecontent)
		if err != nil {
			return errors.New("Error decrypting FileContent struct")
		}
		filecontent.Contents = content

		// encryption filecontent
		filecontent_ciphertext, filecontent_HMAC, err := EncryptAndHMAC(FileContent_Dec_Key, filecontent)
		// upload file content
		userlib.DatastoreSet(userFI.Start_file_contents_UUID, filecontent_ciphertext)
		userlib.DatastoreSet(filecontent_HMAC_UUID, filecontent_HMAC)

		newFileInfo_Sig_UUID, err := uuidAndStringToFromBytesUUID(userFI_UUID, "Signature")

		// generate key for file contents, use filename + "FileContent" as salt
		FileContentKey, err := userlib.HashKDF(userdata.userkey, []byte(filename+"FileContent"))
		if err != nil {
			return errors.New("Error generating key for file contents")
		}

		// generate UUIDS for the filecontents
		startFC_UUID := uuid.New()
		startFC_HMAC_UUID, err := uuidAndStringToFromBytesUUID(startFC_UUID, "HMAChmac")
		if err != nil {
			return errors.New("Error generating UUID for start FC HMAC struct")
		}

		nextFC_UUID := uuid.New()
		nextFC_HMAC_UUID, err := uuidAndStringToFromBytesUUID(nextFC_UUID, "HMAChmac")
		if err != nil {
			return errors.New("Error generating UUID for next FC HMAC struct")
		}

		// set the UUIDs
		userFI.Start_file_contents_UUID = startFC_UUID
		userFI.Next_file_contents_UUID = nextFC_UUID

		// generate a key for FileInfo Encryption
		FileInfo_Encryption_Key := userlib.Argon2Key(userdata.userkey, []byte(filename+"FileInfo"), 16)
		// FileInfo Encryption
		newFileInfo_Ciphertext, newFileInfo_Sig, err := EncryptAndSign(userdata.DSSignKey, FileInfo_Encryption_Key, userFI)

		// NOW NEED TO CREATE NEW FILE CONTENT STRUCTS, uuid is startFC_UUID
		var newFileContent FileContent
		var nextFileContent FileContent

		// set contents
		newFileContent.Contents = content
		nextFileContent.Contents = nil

		// set next pointer to nextFC
		newFileContent.Next_file_contents_UUID = nextFC_UUID

		// SET next pointer to uuid.Nil
		nextFileContent.Next_file_contents_UUID = uuid.Nil

		// encrypt file content and nextfile Content
		newFileContent_Ciphertext, newFileContent_HMAC, err := EncryptAndHMAC(FileContentKey, newFileContent)
		nextFileContent_Ciphertext, nextFileContent_HMAC, err := EncryptAndHMAC(FileContentKey, nextFileContent)

		// upload file content
		userlib.DatastoreSet(startFC_UUID, newFileContent_Ciphertext)
		userlib.DatastoreSet(startFC_HMAC_UUID, newFileContent_HMAC)
		// upload next file content
		userlib.DatastoreSet(nextFC_UUID, nextFileContent_Ciphertext)
		userlib.DatastoreSet(nextFC_HMAC_UUID, nextFileContent_HMAC)
		// upload file info
		userlib.DatastoreSet(userFI_UUID, newFileInfo_Ciphertext)
		userlib.DatastoreSet(newFileInfo_Sig_UUID, newFileInfo_Sig)
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Step 1: Get the FileName struct from the datastore.
	filenameUUIDBytes := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 16)
	//may need another way in line 325, just keep it like this right now
	filenameUUID, err := uuid.FromBytes(filenameUUIDBytes)

	filename_HMAC_UUID, err := uuidAndStringToFromBytesUUID(filenameUUID, "HMAChmac")

	if err != nil {
		return err
	}

	filename_cipher, ok := userlib.DatastoreGet(filenameUUID)
	if !ok {
		return errors.New("File not found")
	}

	filename_HMAC, ok := userlib.DatastoreGet(filename_HMAC_UUID)
	FileName_Decryption_Key := userlib.Argon2Key(userdata.userkey, []byte(filename+"FileName"), 16)
	var filenameData FileName
	err = HMACAndDecrypt(FileName_Decryption_Key, filename_cipher, filename_HMAC, &filenameData)
	if err != nil {
		return err
	}
	if filenameData.File_pointer == uuid.Nil {
		return errors.New("File not found")
	}

	// Step 2: Use the pointer in filename to find the FileInfo struct. can be simple!!!!!!!
	fileInfoUUID := filenameData.File_pointer

	fileInfo_cipher, ok := userlib.DatastoreGet(fileInfoUUID)
	if !ok {
		return errors.New("File not found")
	}
	FIS_TEMP, err := uuidAndStringToFromBytesUUID(fileInfoUUID, "Signature")

	if err != nil {
		return err
	}
	fileInfo_sig, ok := userlib.DatastoreGet(FIS_TEMP)

	verify_Key, ok := userlib.KeystoreGet(userdata.Username + "DSVerifyKey")
	fileInfo_Dec_Key := userlib.Argon2Key(userdata.userkey, []byte(filename+"FileInfo"), 16)

	var fileInfoData FileInfo
	err = VerifyAndDecrypt(verify_Key, fileInfo_Dec_Key, fileInfo_cipher, fileInfo_sig, fileInfoData)

	// Step 3: Get the FileContents struct by checking Next_file_contents_UUID in FileInfo struct.
	//Get Decryption key
	if fileInfoData.Next_file_contents_UUID == uuid.Nil {
		return errors.New("File contents not found")
	}

	var nextFileContents FileContent
	nextFileContents_UUID := fileInfoData.Next_file_contents_UUID
	nextFileContents_cipher, ok := userlib.DatastoreGet(nextFileContents_UUID)

	nextFileContents_HMAC_UUID, err := uuidAndStringToFromBytesUUID(nextFileContents_UUID, "HMAChmac")

	nextFileContents_HMAC, ok := userlib.DatastoreGet(nextFileContents_HMAC_UUID)
	if ok == false {
		return err
	}

	//Get Decryption key
	if err != nil {
		return err
	}
	//get nextFileContents
	err = HMACAndDecrypt(fileInfoData.Key_for_contents, nextFileContents_cipher, nextFileContents_HMAC, &nextFileContents)
	if err != nil {
		return err
	}

	// Step 4: Put the "append content" into contents in FileContents struct.
	nextFileContents.Contents = content

	// Step 5: Create a new empty FileContents struct and a new UUID for it.
	newEmptyFileContentsUUID := uuid.New()
	// newEmptyFileContents_HMAC_UUID, err := uuid.FromBytes(newEmptyFileContentsUUID + []byte("HMAChmac"))
	newEmptyFileContents_HMAC_UUID, err := uuidAndStringToFromBytesUUID(newEmptyFileContentsUUID, "HMAChmac")

	if err != nil {
		return err
	}

	var newEmptyFileContents FileContent
	newEmptyFileContents.Contents = nil

	// Step 6: Set Next_file_contents_UUID in FileContents to the new UUID (newEmptyFileContentsUUID).
	nextFileContents.Next_file_contents_UUID = newEmptyFileContentsUUID

	// Step 7: Set Next_file_contents_UUID in FileInfo to the new UUID (newEmptyFileContentsUUID).
	fileInfoData.Next_file_contents_UUID = newEmptyFileContentsUUID

	// Step 8: EncryptAndHMAC the new empty FileContents.
	old_nextFile_ciphertext, old_nextFile_hmac, err := EncryptAndHMAC(fileInfoData.Key_for_contents, nextFileContents)
	newEmptyFileContents_ciphertext, newEmptyFileContents_hmac, err := EncryptAndHMAC(fileInfoData.Key_for_contents, newEmptyFileContents)

	// Step 9: Store the new empty FileContents struct in the datastore.
	userlib.DatastoreSet(newEmptyFileContentsUUID, newEmptyFileContents_ciphertext)
	userlib.DatastoreSet(newEmptyFileContents_HMAC_UUID, newEmptyFileContents_hmac)
	userlib.DatastoreSet(nextFileContents_UUID, old_nextFile_ciphertext)
	userlib.DatastoreSet(nextFileContents_HMAC_UUID, old_nextFile_hmac)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Step1 get file name
	var filenameData FileName
	filenameData, err = retrieveFileName(userdata.Username, filename, filenameData, userdata.userkey) // Added missing err declaration

	// Step 2: Get the FileInfo struct using the pointer obtained from the FileName struct.
	fileInfoUUID := filenameData.File_pointer
	fileInfo_cipher, ok := userlib.DatastoreGet(fileInfoUUID)
	if !ok {
		return nil, errors.New("File not found")
	}
	FISTEMP, err := uuidAndStringToFromBytesUUID(fileInfoUUID, "Signature")
	if err != nil {
		return nil, err
	}

	fileInfo_sig, ok := userlib.DatastoreGet(FISTEMP) // Fixed this line to use append()

	verify_Key, ok := userlib.KeystoreGet(userdata.Username + "DSVerifyKey") // Fixed userdata.Username to userdata.username
	fileInfo_Dec_Key := userlib.Argon2Key(userdata.userkey, []byte(filename+"FileInfo"), 16)

	var fileInfoData FileInfo
	err = VerifyAndDecrypt(verify_Key, fileInfo_Dec_Key, fileInfo_cipher, fileInfo_sig, &fileInfoData)
	if err != nil {
		return nil, err
	}

	// Step 3: Get the first FileContents struct using the Start_file_contents_UUID in FileInfo. uuid.Nil is the zero UUID, not nil
	if fileInfoData.Start_file_contents_UUID == uuid.Nil {
		return nil, errors.New("File contents not found")
	}
	var filecontent FileContent
	filecontent_UUID := fileInfoData.Start_file_contents_UUID
	filecontent_cipher, ok := userlib.DatastoreGet(filecontent_UUID)

	filecontent_HMAC_UUID, err := uuidAndStringToFromBytesUUID(filecontent_UUID, "HMAChmac")

	if err != nil {
		return nil, err
	}

	filecontent_HMAC, ok := userlib.DatastoreGet(filecontent_HMAC_UUID)

	// Get Decryption key
	err = HMACAndDecrypt(fileInfoData.Key_for_contents, filecontent_cipher, filecontent_HMAC, &filecontent)
	if err != nil {
		return nil, err
	}

	// Step 4: Concatenate the contents of all FileContents structs until Next_file_contents_UUID is nil.
	for filecontent.Next_file_contents_UUID != uuid.Nil {
		nextFileContentsUUID := filecontent.Next_file_contents_UUID
		nextFileContentsCipher, ok := userlib.DatastoreGet(nextFileContentsUUID)
		if ok == false {
			return nil, err
		}

		nextFileContentsHMACUUID, err := uuidAndStringToFromBytesUUID(nextFileContentsUUID, "HMAChmac")
		if err != nil {
			return nil, err
		}

		nextFileContentsHMAC, ok := userlib.DatastoreGet(nextFileContentsHMACUUID)

		// Decrypt the next FileContents struct.
		var nextFileContents FileContent
		err = HMACAndDecrypt(FileContent_Dec_Key, nextFileContentsCipher, nextFileContentsHMAC, &nextFileContents)
		if err != nil {
			return nil, err
		}

		// Append the contents to the overall content.
		content = append(content, filecontent.Contents...)
		filecontent = nextFileContents
	}

	// Append the contents of the last FileContents struct to the overall content.
	content = append(content, filecontent.Contents...)

	return content, nil
}

// Helper function to retrieve File Information from UUID
func retrieveFileInfo(fileInfoUID uuid.UUID, dec_key []byte, verify_key userlib.DSVerifyKey) (*FileInfo, error) {
	// Retrieve and decrypt the file info
	fileInfoBytes, ok := userlib.DatastoreGet(fileInfoUID)
	if !ok {
		return nil, errors.New("File not found, retrieveFileInfo helper")
	}

	fileInfo_Sig_UUID, err := uuidAndStringToFromBytesUUID(fileInfoUID, "Signature")
	if err != nil {
		return nil, errors.New("Error generating fileInfo_Sig_UUID, retrieveFileInfo helper")
	}

	fileInfo_Sig_Bytes, ok := userlib.DatastoreGet(fileInfo_Sig_UUID)

	var fileInfo FileInfo
	err = VerifyAndDecrypt(verify_key, dec_key, fileInfoBytes, fileInfo_Sig_Bytes, &fileInfo)
	if err != nil {
		return nil, errors.New("Something wrong in VerifyAndDecrypt, retrieveFileInfo helper")
	}

	return &fileInfo, nil
}

func retrieveFileName(username string, filename string, FileName_Decryption_Key []byte) (FileName, error) {

	// empty upon declaration, ok to return for an error
	var filenameData1 FileName
	// Step 1: Generate the UUID for the FileName struct using username and filename.
	fileNameUUIDBytes := userlib.Argon2Key([]byte(username), []byte(filename), 16) // 16 bytes
	fileNameUUID, err := uuid.FromBytes(fileNameUUIDBytes)
	if err != nil {
		return filenameData1, errors.New("Error generating UUID for FileName UUID, retrieveFileName helper")
	}

	fileName_HMAC_UUID, err := uuidAndStringToFromBytesUUID(fileNameUUID, "HMAChmac")
	if err != nil {
		return filenameData1, errors.New("Error generating UUID for FileName HMAC UUID, retrieveFileName helper")
	}

	// Step 2: Check if the filename exists in the user's personal namespace.
	filename_cipher, ok := userlib.DatastoreGet(filenameUUID)
	if !ok {
		return filenameData1, errors.New("File not found, retrieveFileName helper")
	}

	// Step 3: Get the HMAC for the filename and verify its integrity.
	filename_HMAC, ok := userlib.DatastoreGet(filename_HMAC_UUID)
	err = HMACAndDecrypt(FileName_Decryption_Key, filename_cipher, filename_HMAC, &filenameData1)
	if err != nil {
		return filenameData1, errors.New("Error return filenamedata1, retrieveFileName helper")
	}
	return filenameData1, nil
}

// Helper function to store File Information
func storeFileInfo(fileInfo *FileInfo, enc_key []byte, sign_key userlib.DSSignKey, fileInfo_UUID uuid.UUID) error {

	fileInfoCiphertext, fileInfoSig, err := EncryptAndSign(sign_key, enc_key, fileInfo)
	fileInfo_Sig_UUID, err := uuidAndStringToFromBytesUUID(fileInfo_UUID, "Signature")
	if err != nil {
		return err
	}

	// Store the file info
	userlib.DatastoreSet(fileInfo_UUID, fileInfoCiphertext)
	userlib.DatastoreSet(fileInfo_Sig_UUID, fileInfoSig)

	return nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// Step 1: Get the FileName struct from the datastore.
	FileName_Decryption_Key := userlib.Argon2Key(userdata.userkey, []byte(filename+"FileName"), 16)
	filenamedata, err := retrieveFileName(userdata.Username, filename, FileName_Decryption_Key)
	if err != nil {
		return uuid.Nil, errors.New("Error return filenamedata in createinvitation(step1)")
	}

	// Step 2: Check if the recipientUsername is already in the FileName struct's Invitations list.
	for _, invitee := range filenamedata.Invitations {
		if invitee == recipientUsername {
			return uuid.Nil, errors.New("Recipient already invited")
		}
	}
	// Step 3: If the recipientUsername is not in the Invitations list, get the FileInfo struct from the datastore.
	verify_key, ok := userlib.KeystoreGet(userdata.Username + "DSVerifyKey")
	if ok != true {
		return uuid.Nil, errors.New("Key not exist(createInvitation Function step3)")
	}
	fileInfo_Dec_Key := userlib.Argon2Key(userdata.userkey, []byte(filename+"FileInfo"), 16)
	fileInfo, err := retrieveFileInfo(filenamedata.File_pointer, fileInfo_Dec_Key, verify_key)
	if err != nil {
		return uuid.Nil, errors.New("Erro fileInfo in createinvitation(step3)")
	}

	// Step 4: Create a new Invitation struct. (Use a random UUID for the Invitation struct's UUID.) Can not be random.
	// Step 5: Set the Invitation struct's Owner to the current user's username.
	// Step 6: Set the Invitation struct's Intended_user to the recipientUsername.
	// Step 7: Set the Invitation struct's FileInfo_UUID to the FileInfo struct's UUID.
	...
	invitationUUID, err := uuid.FromBytes(userlib.Argon2Key([]byte(userdata.Username+filename), []byte(recipientUsername), 16))
	if err != nil {
		return uuid.Nil, errors.New("Error generating UUID for invitationUUID, createinvitation(step4)")
	}
	invitationData := Invitation{
		Owner:         userdata.Username,
		FileInfo_UUID: fileInfo.Start_file_contents_UUID,
		Receiver:      recipientUsername,
	}

	// Step 8: Encrypt the Invitation struct.
	enc_dec_keyforINVIREVA := userlib.Argon2Key([]byte(userdata.Username+filename+"KeyForEncDecInvitation"), []byte(recipientUsername), 16)
	invitation_cipher, invitation_sig, err := EncryptAndSign(userdata.DSSignKey, enc_dec_keyforINVIREVA, invitationData)

	// Step 9: Store the encrypted Invitation struct in the datastore.
	userlib.DatastoreSet(invitationUUID, invitation_cipher)
	invitation_Sig_UUID, err := uuidAndStringToFromBytesUUID(invitationUUID, "Signature")
	if err != nil {
		return uuid.Nil, errors.New("invitation_Sig_UUID Wrong createInivitation Function step 9")
	}
	userlib.DatastoreSet(invitation_Sig_UUID, invitation_sig)

	// Step 10: Append the recipientUsername to the Invitations list in the FileName struct.
	filenamedata.Invitations = append(filenamedata.Invitations, recipientUsername)

	// Step 11: Encrypt the FileName struct.
	filename_ciphertext, filename_HMAC, err := EncryptAndHMAC(FileName_Decryption_Key, &filenamedata)
	if err != nil {
		return uuid.Nil, errors.New("filename_ciphertext, filename_HMAC Wrong createInivitation Function step 11")
	}

	// Step 12: Store the encrypted FileName struct in the datastore.
	fileNameUUIDBytes := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 16) // 16 bytes
	fileNameUUID, err := uuid.FromBytes(fileNameUUIDBytes)
	if err != nil {
		return uuid.Nil, errors.New("Error generating UUID for FileName UUID, createInivitation Function step 12")
	}

	fileName_HMAC_UUID, err := uuidAndStringToFromBytesUUID(fileNameUUID, "HMAChmac")
	if err != nil {
		return uuid.Nil, errors.New("Error generating UUID for FileName HMAC UUID, createInivitation Function step 12")
	}
	userlib.DatastoreSet(fileNameUUID, filename_ciphertext)
	userlib.DatastoreSet(fileName_HMAC_UUID, filename_HMAC)

	// Step 13: Return the Invitation struct's UUID.
	return invitationUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Step 1: Get the Invitation struct from the datastore. (Maybe have to unlock using their username?)
	enc_dec_keyforINVIREVA := userlib.Argon2Key([]byte(senderUsername+filename+"KeyForEncDecInvitation"), []byte(userdata.Username), 16)
	invitationUUID, err := uuid.FromBytes(userlib.Argon2Key([]byte(senderUsername+filename), []byte(userdata.Username), 16))
	if err != nil {
		return errors.New("Error generating UUID for invitationUUID, AcceptInvitation(step1)")
	}
	invitation_Sig_UUID, err := uuidAndStringToFromBytesUUID(invitationUUID, "Signature")
	if err != nil {
		return errors.New("Error generating invitation_Sig_UUID, AcceptInvitation(step1)")
	}
	verify_key, ok := userlib.KeystoreGet(senderUsername + "DSVerifyKey")
	if ok != true {
		return errors.New("Error getting vervication key, AcceptInvitation(step1)")
	}
	invitation_cipher, ok := userlib.DatastoreGet(invitationUUID)
	if ok != true {
		return errors.New("Error getting invitation_cipher, AcceptInvitation(step1)")
	}
	invitation_sig, ok := userlib.DatastoreGet(invitation_Sig_UUID)
	if ok != true {
		return errors.New("Error getting invitation_sig, AcceptInvitation(step1)")
	}
	var invitationData Invitation
	err = VerifyAndDecrypt(verify_key, enc_dec_keyforINVIREVA, invitation_cipher, invitation_sig, invitationData)

	// Step 2: Verify that the Invitation struct's Intended_user is the current user's username.
	if invitationData.Receiver != userdata.Username {
		return errors.New("Invitation not intended for this user")
	}

	// Step 3: verify that the Invitation struct's Owner is the senderUsername.
	if invitationData.Owner != senderUsername {
		return errors.New("Invalid invitation sender")
	}

	// Step 4: create a new FileName struct (UUID is PBKDF of userdata.username and filename).
	// Step 5: Set the new FileName struct's File_pointer to the FileInfo struct's UUID (Found in the invitation).
	newFileName := FileName{
		Owner:        senderUsername,
		File_pointer: invitationData.FileInfo_UUID,
		Invitations:  []string{},
	}

	// Step 6: Store filename to datastore
	FileName_Decryption_Key := userlib.Argon2Key(userdata.userkey, []byte(filename+"FileName"), 16)
	filename_ciphertext, filename_HMAC, err := EncryptAndHMAC(FileName_Decryption_Key, newFileName)
	if err != nil {
		return errors.New("Error generating filename_ciphertext and filename_HMAC, AcceptInvitation(step6)")
	}
	fileNameUUIDBytes := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 16)
	fileNameUUID, err := uuid.FromBytes(fileNameUUIDBytes)
	if err != nil {
		return errors.New("Error generating UUID for FileName UUID, AcceptInvitation(step6)")
	}

	fileName_HMAC_UUID, err := uuidAndStringToFromBytesUUID(fileNameUUID, "HMAChmac")
	if err != nil {
		return errors.New("Error generating UUID for FileName HMAC, AcceptInvitation(step6)")
	}
	userlib.DatastoreSet(fileNameUUID, filename_ciphertext)
	userlib.DatastoreSet(fileName_HMAC_UUID, filename_HMAC)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Step 1: Get the FileName struct from the datastore.
	FileName_Decryption_Key := userlib.Argon2Key(userdata.userkey, []byte(filename+"FileName"), 16)
	filenamedata, err := retrieveFileName(userdata.Username, filename, FileName_Decryption_Key)
	if err != nil {
		return errors.New("Error retrieving FileName in RevokeAccess(step1)")
	}

	// Step 2: Check if the recipientUsername is in the Invitations list.
	// Step 3: If the recipientUsername is in the Invitations list, remove it from the Invitations list.
	FileName_Decryption_Key := userlib.Argon2Key(userdata.userkey, []byte(filename+"FileName"), 16)
	filenamedata, err := retrieveFileName(userdata.Username, filename, FileName_Decryption_Key)
	if err != nil {
		return errors.New("Error return filenamedata in RevokeAccess(step1)")
	}
	found := false
	newInvitations := []string{}
	for _, invitee := range filenamedata.Invitations {
		if invitee == recipientUsername {
			found = true
		} else {
			newInvitations = append(newInvitations, invitee)
		}
	}
	filenamedata.Invitations = newInvitations

	// Step 4: get the FileInfo struct from the datastore (UUID in the FileName struct).
	verify_key, ok := userlib.KeystoreGet(userdata.Username + "DSVerifyKey")
	if !ok {
		return errors.New("Error retrieving DSVerifyKey in RevokeAccess(step4)")
	}
	fileInfo_Dec_Key := userlib.Argon2Key(userdata.userkey, []byte(filename+"FileInfo"), 16)
	oldFileInfo, err := retrieveFileInfo(filenamedata.File_pointer, fileInfo_Dec_Key, verify_key)
	if err != nil {
		return errors.New("Error retrieving oldFileInfo in RevokeAccess(step4)")
	}

	// Step 5: Create a new FileInfo struct (UUID is random) (Information from the old FileInfo struct)
	fileInfoUUID = uuid.New()
	fileInfo_Sig_UUID, err := uuidAndStringToFromBytesUUID(fileInfoUUID, "Signature")
	var newFileInfo FileInfo
	newFileInfo.Owner = userdata.Username
	newFileInfo.Start_file_contents_UUID = oldFileInfo.Start_file_contents_UUID
	newFileInfo.Next_file_contents_UUID = oldFileInfo.Next_file_contents_UUID

	// Step 6: Create new key used to decrypt FileContents and store it in new FileInfo struct (Should make helpful function to get all FileContents)
	FileContentKey, err := userlib.HashKDF(oldFileInfo.Key_for_contents, []byte("RevokeAccess"+recipientUsername))
	if err != nil {
		return errors.New("Error generating key for file contents in RevokeAccess(step6)")
	}
	FileContentKey = FileContentKey[:16]
	newFileInfo.Key_for_contents = FileContentKey

	// Step 7: Re-encrpyt the FileContents using the new key
	//decrypt&encrypt again for first filecontent
	startFC_HMAC_UUID, err := uuidAndStringToFromBytesUUID(newFileInfo.Start_file_contents_UUID, "HMAChmac")

	var filecontent FileContent
	filecontent_UUID := oldFileInfo.Start_file_contents_UUID
	filecontent_cipher, ok := userlib.DatastoreGet(filecontent_UUID)
	filecontent_HMAC, ok := userlib.DatastoreGet(startFC_HMAC_UUID)

	err = HMACAndDecrypt(oldFileInfo.Key_for_contents, filecontent_cipher, filecontent_HMAC, &filecontent)
	if err != nil {
		return errors.New("Something wrong when HMACAndDecrypt in RevokeAccess(step7) ")
	}

	newFileContent_Ciphertext, newFileContent_HMAC, err := EncryptAndHMAC(newFileInfo.Key_for_contents, filecontent)
	if err != nil {
		return errors.New("Something wrong when EncryptandHmac in RevokeAccess(step7) ")
	}
	userlib.DatastoreSet(newFileInfo.Start_file_contents_UUID, newFileContent_Ciphertext)
	userlib.DatastoreSet(startFC_HMAC_UUID, newFileContent_HMAC)

	// decrypt&encrypt again for all filecontent
	for filecontent.Next_file_contents_UUID != uuid.Nil {
		nextFileContentsUUID := filecontent.Next_file_contents_UUID
		nextFileContentsCipher, ok := userlib.DatastoreGet(nextFileContentsUUID)
		if ok == false {
			return errors.New("File contents not found in RevokeAccess(step7)")
		}

		nextFileContentsHMACUUID, err := uuidAndStringToFromBytesUUID(nextFileContentsUUID, "HMAChmac")
		if err != nil {
			return errors.New("erro nextFileContentsHMACUUID in RevokeAccess(step7)")
		}

		nextFileContentsHMAC, ok := userlib.DatastoreGet(nextFileContentsHMACUUID)

		// Decrypt the next FileContents struct.
		var nextFileContents FileContent
		err = HMACAndDecrypt(oldFileInfo.Key_for_contents, nextFileContentsCipher, nextFileContentsHMAC, &nextFileContents)
		if err != nil {
			return errors.New("erro nextFileContentsHMACUUID in RevokeAccess(step7)")
		}

		newNextFileContent_Ciphertext, newNextFileContent_HMAC, err := EncryptAndHMAC(newFileInfo.Key_for_contents, nextFileContents)
		if err != nil {
			return errors.New("Something wrong when EncryptandHmac in RevokeAccess(step7) ")
		}
		userlib.DatastoreSet(nextFileContentsUUID, newNextFileContent_Ciphertext)
		userlib.DatastoreSet(nextFileContentsHMACUUID, newNextFileContent_HMAC)

		filecontent = nextFileContents
		...
	}
	return nil
}
