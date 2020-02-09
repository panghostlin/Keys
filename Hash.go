/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Tuesday 28 January 2020 - 22:29:42
** @Filename:				Hash.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Wednesday 05 February 2020 - 13:05:05
*******************************************************************************/

package			main

import			"os"
import			"crypto/aes"
import			"crypto/cipher"
import			"encoding/hex"
import			"golang.org/x/crypto/argon2"
import			"github.com/microgolang/logs"

/******************************************************************************
**	Convert a password to two hashes, argon2 and scrypt
**	which will later be used to log-in the member by a comparison between
**	it's password and the hashes
******************************************************************************/
func	GeneratePasswordHash(password string) ([]byte, []byte, cipher.Block, error) {
	/**************************************************************************
	**	Get the master key from the .env file
	**************************************************************************/
	MasterKey, err := hex.DecodeString(os.Getenv("MASTER_KEY"))
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, err
	}

	/**************************************************************************
	**	Create a Cipher with the master key
	**************************************************************************/
	block, err := aes.NewCipher(MasterKey)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, err
	}

	/**************************************************************************
	**	Generate the argon2 and scrypt hash from the password
	**************************************************************************/
	argon2Hash, scryptHash, err := hashMemberPassword(password)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, err
	}

	/**************************************************************************
	**	Add the padding to the hash to avoid decryption issues
	**************************************************************************/
	argon2Hash, err = pkcs7Pad(argon2Hash, block.BlockSize())
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, err
	}
	scryptHash, err = pkcs7Pad(scryptHash, block.BlockSize())
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, err
	}
	return argon2Hash, scryptHash, block, nil
}

/******************************************************************************
**	Symetric encryption. Encrypt the hashes with a MasterKey to ensure database
**	security
******************************************************************************/
func	EncryptPasswordHash(plainArgon2Hash, plainScryptHash []byte, block cipher.Block) ([]byte, []byte, []byte, []byte, error){
	/**************************************************************************
	**	Generate an Initialization Vector to perform the CTR AES Encryption
	**************************************************************************/
	argon2IV, err := generateNonce(aes.BlockSize)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, nil, err
	}
	scryptIV, err := generateNonce(aes.BlockSize)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, nil, err
	}

	/**************************************************************************
	**	Perform the actual encryption
	**************************************************************************/
	argon2Hash := make([]byte, len(plainArgon2Hash))
	argon2Enc := cipher.NewCBCEncrypter(block, argon2IV)
	argon2Enc.CryptBlocks(argon2Hash, plainArgon2Hash)
	scryptHash := make([]byte, len(plainScryptHash))
	scryptEnc := cipher.NewCBCEncrypter(block, scryptIV)
	scryptEnc.CryptBlocks(scryptHash, plainScryptHash)

	return argon2Hash, argon2IV, scryptHash, scryptIV, nil
}

/******************************************************************************
**	Symetric encryption. Decrypt the hashes, from the database, with the
**	MasterKey to get the plain hashes
******************************************************************************/
func	DecryptPasswordHash(argon2Hash, argon2IV, scryptHash, scryptIV []byte) ([]byte, []byte, error) {
	/**************************************************************************
	**	Get the master key from the .env file
	**************************************************************************/
	MasterKey, err := hex.DecodeString(os.Getenv("MASTER_KEY"))
	if (err != nil) {
		logs.Error(err)
		return nil, nil, err
	}

	/**************************************************************************
	**	Create a Cipher with the master key
	**************************************************************************/
	block, err := aes.NewCipher(MasterKey)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, err
	}

	/**************************************************************************
	**	Decrypt the ciphertext
	**************************************************************************/
	argon2UnHash := make([]byte, len(argon2Hash))
	argon2Dec := cipher.NewCBCDecrypter(block, argon2IV)
	argon2Dec.CryptBlocks(argon2UnHash, argon2Hash)

	scryptUnHash := make([]byte, len(scryptHash))
	scryptDec := cipher.NewCBCDecrypter(block, scryptIV)
	scryptDec.CryptBlocks(scryptUnHash, scryptHash)

	/**************************************************************************
	**	Unpad the result
	**************************************************************************/
	argon2UnHash, _ = pkcs7Unpad(argon2UnHash, aes.BlockSize)
	scryptUnHash, _ = pkcs7Unpad(scryptUnHash, aes.BlockSize)

	return argon2UnHash, scryptUnHash, nil
}


/******************************************************************************
**	Take the user password and encrypt to get a salt and hash. Will be used to
**	encrypt files. Hash will not be stored. We will only be able to get it back
**	from the user password
******************************************************************************/
func	GenerateKeyHash(password string) ([]byte, []byte, error) {
	_, salt, hash, err := generateArgon2HashFromPassword(password)
    if (err != nil) {
        return nil, nil, err
	}
	return salt, hash, nil
}
/******************************************************************************
**	Take a key (the user password) and a salt to get the encryption hash used
**	to encrypt files
******************************************************************************/
func	GetHashFromKey(key, salt []byte) ([]byte) {
	return argon2.IDKey(key, salt, argon2Parameters.iterations, argon2Parameters.memory, argon2Parameters.parallelism, argon2Parameters.keyLength)
}