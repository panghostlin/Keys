/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Tuesday 07 January 2020 - 12:58:28
** @Filename:				service.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Saturday 15 February 2020 - 15:05:59
*******************************************************************************/

package			main

import (
	"os"
	"context"
	"errors"
	"encoding/base64"
	"runtime/debug"
	"github.com/microgolang/logs"
	"github.com/panghostlin/SDK/Keys"
	P "github.com/microgolang/postgre"
)

func (s *server) CreateKeys(ctx context.Context, req *keys.CreateKeysRequest) (*keys.CreateKeysResponse, error) {
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
		return &keys.CreateKeysResponse{}, err
	}
	encryptionSalt, encryptionHash, err := GenerateKeyHash(req.GetPassword())
	if (err != nil) {
		return &keys.CreateKeysResponse{}, err
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
		return &keys.CreateKeysResponse{}, err
	}

	publicKey, err := encodePublicKey(&privateKey.PublicKey)
	if (err != nil) {
		logs.Error(err)
		return &keys.CreateKeysResponse{}, err
	}

	publicKeyBytes := []byte(publicKey)
	privateKeyBytes := encodePrivateKey(privateKey)

	publicEncrypted, publicIV, err := EncryptPublicKey(publicKeyBytes, os.Getenv("MASTER_PUBLIC_KEY"))
	if (err != nil) {
		logs.Error(err)
		return &keys.CreateKeysResponse{}, err
	}

	privateEncrypted, privateIV, privateSalt, err := EncryptPrivateKey(privateKeyBytes, encryptionHash)
	if (err != nil) {
		logs.Error(err)
		return &keys.CreateKeysResponse{}, err
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

	return &keys.CreateKeysResponse{HashKey: base64.RawStdEncoding.EncodeToString(encryptionHash)}, nil
}
func (s *server) CheckPassword(ctx context.Context, req *keys.CheckPasswordRequest) (*keys.CheckPasswordResponse, error) {
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
		return &keys.CheckPasswordResponse{}, err
	}

	PasswordArgon2Hash, _ := base64.RawStdEncoding.DecodeString(B64PasswordArgon2Hash)
	PasswordArgon2IV, _ := base64.RawStdEncoding.DecodeString(B64PasswordArgon2IV)
	PasswordScryptHash, _ := base64.RawStdEncoding.DecodeString(B64PasswordScryptHash)
	PasswordScryptIV, _ := base64.RawStdEncoding.DecodeString(B64PasswordScryptIV)
	EncryptionSalt, _ := base64.RawStdEncoding.DecodeString(B64EncryptionSalt)

	argon2Hash, scryptHash, err := DecryptPasswordHash(PasswordArgon2Hash, PasswordArgon2IV, PasswordScryptHash, PasswordScryptIV)
	if (err != nil) {
		logs.Error(`Impossible to decode member hash`, err)
		return &keys.CheckPasswordResponse{}, err
	}

	hashMatches := verifyMemberPasswordHash(req.GetPassword(), string(argon2Hash), string(scryptHash))
	if (!hashMatches) {
		logs.Error(`Impossible to verify hash`)
		return &keys.CheckPasswordResponse{}, errors.New(`The hashes does not matches`)
	}

	encryptionHash := GetHashFromKey([]byte(req.GetPassword()), EncryptionSalt)

	return &keys.CheckPasswordResponse{HashKey: base64.RawStdEncoding.EncodeToString(encryptionHash)}, nil
}

func (s *server) GetPublicKey(ctx context.Context, req *keys.GetPublicKeyRequest) (*keys.GetPublicKeyResponse, error) {
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
		return &keys.GetPublicKeyResponse{}, err
	}

	/**************************************************************************
	**	2. Decrypt the user's public Key
	**************************************************************************/
	PublicKey, _ := base64.RawStdEncoding.DecodeString(B64PublicKey)
	PublicKeyIV, _ := base64.RawStdEncoding.DecodeString(B64PublicKeyIV)
	publicDecrypted, err := DecryptPublicKey(PublicKey, PublicKeyIV, os.Getenv("MASTER_PUBLIC_KEY"))
	if (err != nil) {
		logs.Error(`Impossible to decrypt the public key`, err)
		return &keys.GetPublicKeyResponse{}, err
	}

	return &keys.GetPublicKeyResponse{PublicKey: string(publicDecrypted)}, nil
}
func (s *server) GetPrivateKey(ctx context.Context, req *keys.GetPrivateKeyRequest) (*keys.GetPrivateKeyResponse, error) {
	var B64PrivateKey string
	var B64PrivateKeySalt string
	var B64PrivateKeyIV string
	var B64EncryptionSalt string
	
	/**************************************************************************
	**	1. Get the memberID Keys
	**************************************************************************/
	err := P.NewSelector(PGR).Select(`PrivateKey`, `PrivateKeySalt`, `PrivateKeyIV`, `EncryptionSalt`).From(`keys`).
	Where(P.S_SelectorWhere{Key: `MemberID`, Value: req.GetMemberID()}).
	One(&B64PrivateKey, &B64PrivateKeySalt, &B64PrivateKeyIV, &B64EncryptionSalt)
	if (err != nil) {
		logs.Error(`Impossible to find member`, err)
		return &keys.GetPrivateKeyResponse{}, err
	}

	/**************************************************************************
	**	2. Decrypt the user's public Key
	**************************************************************************/
	decodedHashKey, err := base64.RawStdEncoding.DecodeString(req.GetHashKey())
	if (err != nil) {
		logs.Error(`Impossible to decode hashKey`, err)
		return &keys.GetPrivateKeyResponse{}, err
	}

	PrivateKey, _ := base64.RawStdEncoding.DecodeString(B64PrivateKey)
	PrivateKeySalt, _ := base64.RawStdEncoding.DecodeString(B64PrivateKeySalt)
	PrivateKeyIV, _ := base64.RawStdEncoding.DecodeString(B64PrivateKeyIV)
	EncryptionSalt, _ := base64.RawStdEncoding.DecodeString(B64EncryptionSalt)
	privateDecrypted, err := DecryptPrivateKey(PrivateKey, PrivateKeySalt, PrivateKeyIV, decodedHashKey, EncryptionSalt)
	debug.FreeOSMemory()
	if (err != nil) {
		logs.Error(`Impossible to decrypt the private key`, err)
		return &keys.GetPrivateKeyResponse{}, err
	}

	return &keys.GetPrivateKeyResponse{PrivateKey: string(privateDecrypted)}, nil
}
func (s *server) GetKeys(ctx context.Context, req *keys.GetKeysRequest) (*keys.GetKeysResponse, error) {
	var	B64PublicKey string
	var	B64PublicKeyIV string
	var B64PrivateKey string
	var B64PrivateKeySalt string
	var B64PrivateKeyIV string
	var B64EncryptionSalt string
	
	/**************************************************************************
	**	1. Get the memberID Keys
	**************************************************************************/
	err := P.NewSelector(PGR).Select(`PublicKey`, `PublicKeyIV`, `PrivateKey`, `PrivateKeySalt`, `PrivateKeyIV`, `EncryptionSalt`).From(`keys`).
	Where(P.S_SelectorWhere{Key: `MemberID`, Value: req.GetMemberID()}).
	One(&B64PublicKey, &B64PublicKeyIV, &B64PrivateKey, &B64PrivateKeySalt, &B64PrivateKeyIV, &B64EncryptionSalt)
	if (err != nil) {
		logs.Error(`Impossible to find member`, err)
		return &keys.GetKeysResponse{}, err
	}

	/**************************************************************************
	**	2. Decrypt the user's hash Key
	**************************************************************************/
	decodedHashKey, err := base64.RawStdEncoding.DecodeString(req.GetHashKey())
	if (err != nil) {
		logs.Error(`Impossible to decode hashKey`, err)
		return &keys.GetKeysResponse{}, err
	}

	PublicKey, _ := base64.RawStdEncoding.DecodeString(B64PublicKey)
	PublicKeyIV, _ := base64.RawStdEncoding.DecodeString(B64PublicKeyIV)
	PrivateKey, _ := base64.RawStdEncoding.DecodeString(B64PrivateKey)
	PrivateKeySalt, _ := base64.RawStdEncoding.DecodeString(B64PrivateKeySalt)
	PrivateKeyIV, _ := base64.RawStdEncoding.DecodeString(B64PrivateKeyIV)
	EncryptionSalt, _ := base64.RawStdEncoding.DecodeString(B64EncryptionSalt)

	/**************************************************************************
	**	3. Decrypt the user's private and public keys
	**************************************************************************/
	publicDecrypted, err := DecryptPublicKey(PublicKey, PublicKeyIV, os.Getenv("MASTER_PUBLIC_KEY"))
	if (err != nil) {
		logs.Error(`Impossible to decrypt the public key`, err)
		return &keys.GetKeysResponse{}, err
	}
	privateDecrypted, err := DecryptPrivateKey(PrivateKey, PrivateKeySalt, PrivateKeyIV, decodedHashKey, EncryptionSalt)
	if (err != nil) {
		logs.Error(`Impossible to decrypt the private key`, err)
		return &keys.GetKeysResponse{}, err
	}
	debug.FreeOSMemory()

	return &keys.GetKeysResponse{PublicKey: string(publicDecrypted), PrivateKey: string(privateDecrypted)}, nil
}
