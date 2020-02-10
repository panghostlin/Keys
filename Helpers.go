/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Monday 06 January 2020 - 13:39:27
** @Filename:				Helpers.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Monday 10 February 2020 - 14:50:00
*******************************************************************************/

package			main

import			"bytes"
import			"os"
import			"fmt"
import			"github.com/microgolang/logs"
import			"crypto/rand"
import			"crypto/rsa"
import			"crypto/cipher"
import			"encoding/base64"
import			"golang.org/x/crypto/blake2b"

func	pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

func	pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}

func	decryptWithPrivateKey(data []byte, key string, priv *rsa.PrivateKey) []byte {
	/**************************************************************************
	**	We have the encrypted data, aka the image, and a key
	**	We will need to extract the original CipherText and the original IV
	**	from the key.
	**************************************************************************/
	ciphertext, IV, err := DecodeCipherKey(key)
	if (err != nil) {
		logs.Error(err)
		return nil
	}

	/**************************************************************************
	**	Now that we have the original cipher and the original IV, we will use
	**	the private key to decrypt the AES key to perfom the file uncryption.
	**************************************************************************/
	privKey, _ := base64.RawStdEncoding.DecodeString(os.Getenv("PRIV_KEY"))
	hash, _ := blake2b.New512([]byte(privKey))
	secretKey, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if (err != nil) {
		logs.Error(err)
		return nil
	}

	/**************************************************************************
	**	We now have the picture data, the IV and the key used to perform the
	**	AES encryption on the image data.
	**************************************************************************/
	decryptedData, err := DecryptData(data, IV, secretKey)
	if (err != nil) {
		logs.Error(err)
		return nil
	}

	return decryptedData
}
func	encryptWithPublicKey(data []byte, pub *rsa.PublicKey) ([]byte, string) {
	/**************************************************************************
	**	Encrypt the data with AES. We will use the encrypted data as new data
	**	for the picture.
	**	The IV and the secretKey will be used to decrypt AES encrypted data,
	**	AKA the first return argument
	**************************************************************************/
	encryptedData, IV, secretKey, err := EncryptData(data)
	if (err != nil) {
		logs.Error(err)
		return nil, ``
	}

	/**************************************************************************
	**	We can now encrypt the secret key with the user public key.
	**	This new cipher will only be decryptable by the user private key
	**************************************************************************/
	privKey, _ := base64.RawStdEncoding.DecodeString(os.Getenv("PRIV_KEY"))
	hash, _ := blake2b.New512([]byte(privKey))
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, secretKey, nil)
	if (err != nil) {
		logs.Error(err)
		return nil, ``
	}

	/**************************************************************************
	**	We returns the encryptedData (AES) and a string containing the IV and
	**	the cipher, in order to allow the user to decrypt correctly the AES
	**	key with it's private key and the cipher.
	**************************************************************************/
    b64Ciphertext := base64.RawStdEncoding.EncodeToString(ciphertext)
    b64IV := base64.RawStdEncoding.EncodeToString(IV)
	return encryptedData, fmt.Sprintf("$%s$%s", b64Ciphertext, b64IV)
}


func	getUserPasswordHashes(userPassword string, block cipher.Block) ([]byte, []byte, error) {
	argon2Hash, scryptHash, err := hashMemberPassword(userPassword)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, err
	}

	argon2Hash, err = pkcs7Pad(argon2Hash, block.BlockSize())
	if (err != nil) {
		logs.Error(err)
		return nil, nil, err
	}
	scryptHash, err = pkcs7Pad(scryptHash, block.BlockSize())
	if (err != nil) {
		logs.Error(err)
		return nil, nil, err
	}
	return argon2Hash, scryptHash, nil
}
