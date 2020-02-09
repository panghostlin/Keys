/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Tuesday 07 January 2020 - 12:58:28
** @Filename:				service.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Friday 07 February 2020 - 12:30:27
*******************************************************************************/

package			main

import (
	"os"
	"io"
	"context"
	"errors"
	"runtime/debug"
	"encoding/base64"
	"github.com/microgolang/logs"
	P "github.com/microgolang/postgre"
)

func (s *server) CreateKeys(ctx context.Context, req *CreateKeysRequest) (*CreateKeysResponse, error) {
	defer ctx.Done()
	/**************************************************************************
	**	We take the user password, we hash it with two different methods in
	**	order to avoid collisions, with two different IV and one master key,
	**	in order to avoid decryption by matching the keys.
	**	To check the password on login, we will check each hash to find if
	**	they matches the ones we have.
	**
	**	WARNING : If we lost the master key, it will not be possible to
	**	decrypt existing passwords.
	**	IMPROVEMENT : use two different master key, one for each hash
	**	algorithm.
	**************************************************************************/
	plainArgon2Hash, plainScryptHash, block, err := GeneratePasswordHash(req.GetPassword())
	argon2Hash, argon2IV, scryptHash, scryptIV, err := EncryptPasswordHash(plainArgon2Hash, plainScryptHash, block)
	if (err != nil) {
		return &CreateKeysResponse{Success: false}, nil
	}
	encryptionSalt, encryptionHash, err := GenerateKeyHash(req.GetPassword())
	if (err != nil) {
		return &CreateKeysResponse{Success: false}, nil
	}

	memberSecure := &MemberSecure{
		Password:			req.GetPassword(),
		PasswordArgon2Hash:	argon2Hash,
		PasswordArgon2IV:	argon2IV,
		PasswordScryptHash:	scryptHash,
		PasswordScryptIV:	scryptIV,
	}

	/**************************************************************************
	**	We are now using the RSA to create an asymmetric key, in order to use
	**	the public key to encrypt the data for the user, and it's private
	**	key to decrypt it.
	**	The public key is encoded with another master key, different from the
	**	hash one, in order to avoid having it working in the wild.
	**	The private key is encoded with the user password =========================> Should be plain or encrypted ?
	**	then with another master key :
	**	Private key -> Hashed by user with user secret -> hashed by us
	**
	**	This means that we do not know the first key to decrypt the private
	**	key, only the user does, and we are adding a security layer, to avoid
	**	the key being broken if in the wild.
	**
	**	WARNING : If we lost the master key, it will not be possible to
	**	decrypt existing passwords.
	**	WARNING : What to do if the user changes it's password/key/secret ?
	**************************************************************************/
	bitSize := 4096
	privateKey, err := generatePrivateKey(bitSize)
	if (err != nil) {
		logs.Error(err)
		return &CreateKeysResponse{Success: false}, err
	}

	publicKey, err := encodePublicKey(&privateKey.PublicKey)
	if (err != nil) {
		logs.Error(err)
		return &CreateKeysResponse{Success: false}, err
	}

	publicKeyBytes := []byte(publicKey)
	privateKeyBytes := encodePrivateKey(privateKey)

	publicEncrypted, publicIV, err := EncryptPublicKey(publicKeyBytes, os.Getenv("MASTER_PUBLIC_KEY"))
	if (err != nil) {
		logs.Error(err)
		return &CreateKeysResponse{Success: false}, err
	}

	privateEncrypted, privateIV, privateSalt, err := EncryptPrivateKey(privateKeyBytes, encryptionHash)
	if (err != nil) {
		logs.Error(err)
		return &CreateKeysResponse{Success: false}, err
	}

	P.NewInsertor(PGR).Into(`keys`).
	Values(
		P.S_InsertorWhere{Key: `MemberID`, Value: req.GetMemberID()},
		P.S_InsertorWhere{Key: `PasswordArgon2Hash`, Value: base64.RawStdEncoding.EncodeToString(memberSecure.PasswordArgon2Hash)},
		P.S_InsertorWhere{Key: `PasswordArgon2IV`, Value: base64.RawStdEncoding.EncodeToString(memberSecure.PasswordArgon2IV)},
		P.S_InsertorWhere{Key: `PasswordScryptHash`, Value: base64.RawStdEncoding.EncodeToString(memberSecure.PasswordScryptHash)},
		P.S_InsertorWhere{Key: `PasswordScryptIV`, Value: base64.RawStdEncoding.EncodeToString(memberSecure.PasswordScryptIV)},
		P.S_InsertorWhere{Key: `EncryptionSalt`, Value: base64.RawStdEncoding.EncodeToString(encryptionSalt)},
		P.S_InsertorWhere{Key: `PublicKey`, Value: base64.RawStdEncoding.EncodeToString(publicEncrypted)},
		P.S_InsertorWhere{Key: `PublicKeyIV`, Value: base64.RawStdEncoding.EncodeToString(publicIV)},
		P.S_InsertorWhere{Key: `PrivateKey`, Value: base64.RawStdEncoding.EncodeToString(privateEncrypted)},
		P.S_InsertorWhere{Key: `PrivateKeyIV`, Value: base64.RawStdEncoding.EncodeToString(privateIV)},
		P.S_InsertorWhere{Key: `PrivateKeySalt`, Value: base64.RawStdEncoding.EncodeToString(privateSalt)},
	).Do()

	return &CreateKeysResponse{Success: true, HashKey: base64.RawStdEncoding.EncodeToString(encryptionHash)}, nil
}
func (s *server) CheckPassword(ctx context.Context, req *CheckPasswordRequest) (*CheckPasswordResponse, error) {
	var	B64PasswordArgon2Hash string
	var	B64PasswordArgon2IV string
	var	B64PasswordScryptHash string
	var	B64PasswordScryptIV string
	var	B64EncryptionSalt string

	defer ctx.Done()

	err := P.NewSelector(PGR).Select(`PasswordArgon2Hash`, `PasswordArgon2IV`, `PasswordScryptHash`, `PasswordScryptIV`, `EncryptionSalt`).From(`keys`).
	Where(P.S_SelectorWhere{Key: `MemberID`, Value: req.GetMemberID()}).
	One(&B64PasswordArgon2Hash, &B64PasswordArgon2IV, &B64PasswordScryptHash, &B64PasswordScryptIV, &B64EncryptionSalt)
	if (err != nil) {
		logs.Error(`Impossible to find member`, err)
		return &CheckPasswordResponse{Success: false}, err
	}

	PasswordArgon2Hash, _ := base64.RawStdEncoding.DecodeString(B64PasswordArgon2Hash)
	PasswordArgon2IV, _ := base64.RawStdEncoding.DecodeString(B64PasswordArgon2IV)
	PasswordScryptHash, _ := base64.RawStdEncoding.DecodeString(B64PasswordScryptHash)
	PasswordScryptIV, _ := base64.RawStdEncoding.DecodeString(B64PasswordScryptIV)
	EncryptionSalt, _ := base64.RawStdEncoding.DecodeString(B64EncryptionSalt)

	argon2Hash, scryptHash, err := DecryptPasswordHash(PasswordArgon2Hash, PasswordArgon2IV, PasswordScryptHash, PasswordScryptIV)
	if (err != nil) {
		logs.Error(`Impossible to decode member hash`, err)
		return &CheckPasswordResponse{Success: false}, err
	}

	success, err := verifyMemberPasswordHash(req.GetPassword(), string(argon2Hash), string(scryptHash))
	if (err != nil) {
		logs.Error(`Impossible to verify hash`, err)
		return &CheckPasswordResponse{Success: false}, err
	}

	encryptionHash := GetHashFromKey([]byte(req.GetPassword()), EncryptionSalt)
	if (err != nil) {
		return &CheckPasswordResponse{Success: false}, nil
	}

	return &CheckPasswordResponse{Success: success, HashKey: base64.RawStdEncoding.EncodeToString(encryptionHash)}, nil
}


func	EncryptPictureOnSuccess(req *EncryptPictureRequest) (*EncryptPictureResponse, error) {
	var	B64PublicKey string
	var	B64PublicKeyIV string

	/**************************************************************************
	**	1. Get the memberID Keys
	**************************************************************************/
	err := P.NewSelector(PGR).Select(`PublicKey`, `PublicKeyIV`).From(`keys`).
	Where(P.S_SelectorWhere{Key: `MemberID`, Value: req.GetMemberID()}).
	One(&B64PublicKey, &B64PublicKeyIV)
	if (err != nil) {
		logs.Error(`Impossible to find member`, err)
		return &EncryptPictureResponse{Success: false}, err
	}

	/**************************************************************************
	**	2. Decrypt the user's public Key
	**************************************************************************/
	PublicKey, _ := base64.RawStdEncoding.DecodeString(B64PublicKey)
	PublicKeyIV, _ := base64.RawStdEncoding.DecodeString(B64PublicKeyIV)
	publicDecrypted, err := DecryptPublicKey(PublicKey, PublicKeyIV, os.Getenv("MASTER_PUBLIC_KEY"))
	if (err != nil) {
		logs.Error(`Impossible to decrypt the public key`, err)
		return &EncryptPictureResponse{Success: false}, err
	}
	publicDecoded := decodePublicKey(publicDecrypted)

	/**************************************************************************
	**	3. Encrypt the data with the user's public key
	**************************************************************************/
	encryptedData, key := encryptWithPublicKey(req.Chunk, publicDecoded)

	/**************************************************************************
	**	4. Let's stream the encrypted data back
	**************************************************************************/

	return &EncryptPictureResponse{Success: true, Key: key, Chunk: encryptedData}, nil
}
func	EncryptPictureReceiver(stream KeysService_EncryptPictureServer) (*EncryptPictureRequest, error) {
	resp := &EncryptPictureRequest{}

	for {
		select {
			case <-stream.Context().Done():
				return nil, stream.Context().Err()
			default:
		}

		req, err := stream.Recv()
		if err == io.EOF {
			return resp, nil
		}
		if err != nil {
			logs.Error("receive error : ", err)
			continue
		}

		resp.Chunk = append(resp.GetChunk(), req.GetChunk()...)
		resp.MemberID = req.GetMemberID()
	}
}
func	EncryptPictureSender(response *EncryptPictureResponse, stream KeysService_EncryptPictureServer) (bool, error) {
	chunkSize := 64 * 1024
	fileSize := len(response.Chunk)

	if (fileSize < chunkSize) {
		if err := stream.Send(response); err != nil {
			logs.Error(err)
			return false, err
		}
	} else {
		chnk := &EncryptPictureResponse{Success: response.Success, Key: response.Key}
		for currentByte := 0; currentByte < fileSize; currentByte += chunkSize {
			if currentByte + chunkSize > fileSize {
				chnk.Chunk = response.Chunk[currentByte:fileSize]
			} else {
				chnk.Chunk = response.Chunk[currentByte : currentByte + chunkSize]
			}
			if err := stream.Send(chnk); err != nil {
				logs.Error(err)
				return false, err
			}
		}
	}

	return true, nil
}
func (s *server) EncryptPicture(srv KeysService_EncryptPictureServer) error {
	defer srv.Context().Done()

	req, err := EncryptPictureReceiver(srv)
	if (err != nil) {
		return err
	}

	/**************************************************************************
	**	0. Init the stream until we get all the data. Blob will contain the
	**	data, and streamReceiver is the new responder.
	**************************************************************************/	
	response , _ := EncryptPictureOnSuccess(req)
	isSuccess, err := EncryptPictureSender(response, srv)
	if (err != nil || !isSuccess) {
		return err
	}
	
	return nil
}

func	DecryptPictureOnSuccess(req *DecryptPictureRequest) (*DecryptPictureResponse, error) {
	var B64PrivateKey string
	var B64PrivateKeySalt string
	var B64PrivateKeyIV string
	var B64EncryptionSalt string

	/**************************************************************************
	**	1. Get the memberID Keys
	**************************************************************************/
	err := P.NewSelector(PGR).Select(`PrivateKey`, `PrivateKeySalt`, `PrivateKeyIV`, `EncryptionSalt`).
	From(`keys`).
	Where(P.S_SelectorWhere{Key: `MemberID`, Value: req.GetMemberID()}).
	One(&B64PrivateKey, &B64PrivateKeySalt, &B64PrivateKeyIV, &B64EncryptionSalt)
	if (err != nil) {
		logs.Error(`Impossible to find member`, err)
		return &DecryptPictureResponse{Success: false}, err
	}

	/**************************************************************************
	**	2. Decrypt the user's public Key
	**************************************************************************/
	decodedHashKey, err := base64.RawStdEncoding.DecodeString(req.GetHashKey())
	if (err != nil) {
		logs.Error(`Impossible to decode hashKey`, err)
		return &DecryptPictureResponse{Success: false}, err
	}

	PrivateKey, _ := base64.RawStdEncoding.DecodeString(B64PrivateKey)
	PrivateKeySalt, _ := base64.RawStdEncoding.DecodeString(B64PrivateKeySalt)
	PrivateKeyIV, _ := base64.RawStdEncoding.DecodeString(B64PrivateKeyIV)
	EncryptionSalt, _ := base64.RawStdEncoding.DecodeString(B64EncryptionSalt)

	//IF NOT ENOUGH MEMORY AVAILABLE -> CRASH
	privateDecrypted, err := DecryptPrivateKey(PrivateKey, PrivateKeySalt, PrivateKeyIV, decodedHashKey, EncryptionSalt)
	debug.FreeOSMemory()
	//ENDIF NOT ENOUGH MEMORY AVAILABLE -> CRASH

	if (err != nil) {
		logs.Error(`Impossible to decrypt the private key`, err)
		return &DecryptPictureResponse{Success: false}, err
	}
	privateDecoded := decodePrivateKey(privateDecrypted)

	/**************************************************************************
	**	3. Decrypt the data with the user's public key
	**************************************************************************/
	decryptedData := decryptWithPrivateKey(req.GetChunk(), req.GetKey(), privateDecoded)

	/**************************************************************************
	**	4. Let's stream the encrypted data back
	**************************************************************************/
	return &DecryptPictureResponse{Success: true, Chunk: decryptedData}, nil
}
func	DecryptPictureReceiver(stream KeysService_DecryptPictureServer) (*DecryptPictureRequest, error) {
	resp := new(DecryptPictureRequest)

	for {
		select {
			case <-stream.Context().Done():
				return nil, stream.Context().Err()
			default:
		}

		req, err := stream.Recv()
		if err == io.EOF {
			stream.Context().Done()
			return resp, nil
		}
		if err != nil {
			logs.Error("receive error : ", err)
			continue
		}

		resp.Chunk = append(resp.GetChunk(), req.GetChunk()...)
		resp.MemberID = req.GetMemberID()
		resp.HashKey = req.GetHashKey()
		resp.Key = req.GetKey()
	}
}
func	DecryptPictureSender(response *DecryptPictureResponse, stream KeysService_DecryptPictureServer) (bool, error) {
	chunkSize := 64 * 1024
	fileSize := len(response.Chunk)

	if (fileSize < chunkSize) {
		if err := stream.Send(response); err != nil {
			logs.Error(err)
			return false, err
		}
	} else {
		chnk := &DecryptPictureResponse{Success: response.Success}
		
		for currentByte := 0; currentByte < fileSize; currentByte += chunkSize {
			if currentByte + chunkSize > fileSize {
				chnk.Chunk = response.Chunk[currentByte:fileSize]
			} else {
				chnk.Chunk = response.Chunk[currentByte : currentByte + chunkSize]
			}

			if err := stream.Send(chnk); err != nil {
				logs.Error(err)
				return false, err
			}
		}
	}
	return true, nil
}

/******************************************************************************
**	DecryptPicture
**************************************************************************/	
func (s *server) DecryptPicture(srv KeysService_DecryptPictureServer) error {
	defer srv.Context().Done()
	received, err := DecryptPictureReceiver(srv)
	defer received.Reset()

	if (err != nil) {
		return err
	}

	/**************************************************************************
	**	0. Init the stream until we get all the data. Blob will contain the
	**	data, and streamReceiver is the new responder.
	**************************************************************************/	
	response , err := DecryptPictureOnSuccess(received)
	defer response.Reset()
	if (err != nil) {
		return err
	}

	isSuccess, err := DecryptPictureSender(response, srv)
	if (err != nil) {
		return err
	}

	if (!isSuccess) {
		return errors.New(`Decrypt sender failure`)
	}


	return nil
}