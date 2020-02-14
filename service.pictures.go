/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Tuesday 07 January 2020 - 12:58:28
** @Filename:				service.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Friday 14 February 2020 - 18:05:02
*******************************************************************************/

package			main

import (
	"os"
	"io"
	"errors"
	"runtime/debug"
	"encoding/base64"
	"github.com/microgolang/logs"
	"github.com/panghostlin/SDK/Keys"
	P "github.com/microgolang/postgre"
)

/******************************************************************************
**	EncryptPicture
**************************************************************************/	
func	EncryptPictureOnSuccess(req *keys.EncryptPictureRequest) (*keys.EncryptPictureResponse, error) {
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
		return &keys.EncryptPictureResponse{}, err
	}

	/**************************************************************************
	**	2. Decrypt the user's public Key
	**************************************************************************/
	PublicKey, _ := base64.RawStdEncoding.DecodeString(B64PublicKey)
	PublicKeyIV, _ := base64.RawStdEncoding.DecodeString(B64PublicKeyIV)
	publicDecrypted, err := DecryptPublicKey(PublicKey, PublicKeyIV, os.Getenv("MASTER_PUBLIC_KEY"))
	if (err != nil) {
		logs.Error(`Impossible to decrypt the public key`, err)
		return &keys.EncryptPictureResponse{}, err
	}
	publicDecoded := decodePublicKey(publicDecrypted)

	/**************************************************************************
	**	3. Encrypt the data with the user's public key
	**************************************************************************/
	encryptedData, key := encryptWithPublicKey(req.Chunk, publicDecoded)

	/**************************************************************************
	**	4. Let's stream the encrypted data back
	**************************************************************************/

	return &keys.EncryptPictureResponse{Key: key, Chunk: encryptedData}, nil
}
func	EncryptPictureReceiver(stream keys.KeysService_EncryptPictureServer) (*keys.EncryptPictureRequest, error) {
	resp := &keys.EncryptPictureRequest{}

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
func	EncryptPictureSender(response *keys.EncryptPictureResponse, stream keys.KeysService_EncryptPictureServer) (bool, error) {
	chunkSize := 64 * 1024
	fileSize := len(response.Chunk)

	if (fileSize < chunkSize) {
		if err := stream.Send(response); err != nil {
			logs.Error(err)
			return false, err
		}
	} else {
		chnk := &keys.EncryptPictureResponse{Key: response.Key}
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
func (s *server) EncryptPicture(srv keys.KeysService_EncryptPictureServer) error {
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


/******************************************************************************
**	DecryptPicture
**************************************************************************/	
func	DecryptPictureOnSuccess(req *keys.DecryptPictureRequest) (*keys.DecryptPictureResponse, error) {
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
		return &keys.DecryptPictureResponse{}, err
	}

	/**************************************************************************
	**	2. Decrypt the user's hash Key
	**************************************************************************/
	decodedHashKey, err := base64.RawStdEncoding.DecodeString(req.GetHashKey())
	if (err != nil) {
		logs.Error(`Impossible to decode hashKey`, err)
		return &keys.DecryptPictureResponse{}, err
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
		return &keys.DecryptPictureResponse{}, err
	}
	privateDecoded := decodePrivateKey(privateDecrypted)

	/**************************************************************************
	**	3. Decrypt the data with the user's public key
	**************************************************************************/
	decryptedData := decryptWithPrivateKey(req.GetChunk(), req.GetKey(), privateDecoded)

	/**************************************************************************
	**	4. Let's stream the encrypted data back
	**************************************************************************/
	return &keys.DecryptPictureResponse{Chunk: decryptedData}, nil
}
func	DecryptPictureReceiver(stream keys.KeysService_DecryptPictureServer) (*keys.DecryptPictureRequest, error) {
	resp := new(keys.DecryptPictureRequest)

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
func	DecryptPictureSender(response *keys.DecryptPictureResponse, stream keys.KeysService_DecryptPictureServer) (bool, error) {
	chunkSize := 64 * 1024
	fileSize := len(response.Chunk)

	if (fileSize < chunkSize) {
		if err := stream.Send(response); err != nil {
			logs.Error(err)
			return false, err
		}
	} else {
		chnk := &keys.DecryptPictureResponse{}
		
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
func (s *server) DecryptPicture(srv keys.KeysService_DecryptPictureServer) error {
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