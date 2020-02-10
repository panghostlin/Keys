/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Tuesday 28 January 2020 - 21:57:23
** @Filename:				PemKeys.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Monday 10 February 2020 - 14:39:31
*******************************************************************************/

package			main

import			"github.com/microgolang/logs"
import			"crypto/rand"
import			"crypto/aes"
import			"crypto/rsa"
import			"crypto/x509"
import			"crypto/cipher"
import			"encoding/base64"
import			"encoding/pem"

/******************************************************************************
**	GENERATION - GeneratePrivateKey
**	Generate a private key from a random reader based on entropy.
******************************************************************************/
func	generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if (err != nil) {
		return nil, err
	}

	err = privateKey.Validate()
	if (err != nil) {
		return nil, err
	}
	return privateKey, nil
}


/******************************************************************************
**	ENCODING - encodePrivateKey
**	Encode the given privateKey as a PEM key
******************************************************************************/
func	encodePrivateKey(privateKey *rsa.PrivateKey) []byte {
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}
/******************************************************************************
**	ENCODING - decodePrivateKey
**	Decode the given PEM key to original private key
******************************************************************************/
func	decodePrivateKey(privateKey []byte) *rsa.PrivateKey {
	var err error
	block, _ := pem.Decode(privateKey)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes

	if (enc) {
		b, err = x509.DecryptPEMBlock(block, nil)
		if (err != nil) {
			return nil
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if (err != nil) {
		return nil
	}
	return key
}


/******************************************************************************
**	ENCODING - encodePublicKey
**	Encode the given publicKey as a PEM key
******************************************************************************/
func	encodePublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if (err != nil) {
		return nil, err
	}

	pubBlock := pem.Block{
		Type:    "RSA PUBLIC KEY",
		Bytes:   pubASN1,
	}

	publicPEM := pem.EncodeToMemory(&pubBlock)

	return publicPEM, nil
}
/******************************************************************************
**	ENCODING - decodePublicKey
**	Decode the given PEM key to original public key
******************************************************************************/
func	decodePublicKey(publicKey []byte) *rsa.PublicKey {
	var err error
	block, _ := pem.Decode(publicKey)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes

	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if (err != nil) {
			return nil
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if (err != nil) {
		return nil
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil
	}
	return key
}


/******************************************************************************
**	ENCRYPTION - PEM PUBLIC KEY
**	Use AES to encrypt the PEM public Key with the secret key as symmetric
**	key
******************************************************************************/
func	EncryptPublicKey(publicKey []byte, secretKey string) ([]byte, []byte, error) {
	/**************************************************************************
	**	Decode the master key from hex to string
	**************************************************************************/
	secretKeyHex, err := base64.RawStdEncoding.DecodeString(secretKey)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, err
	}

	/**************************************************************************
	**	Create a Cipher with the master key
	**************************************************************************/
	block, err := aes.NewCipher(secretKeyHex)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, err
	}

	/**************************************************************************
	**	Add padding to the key
	**************************************************************************/
	paddedPublicKey, err := pkcs7Pad(publicKey, block.BlockSize())
	if (err != nil) {
		logs.Error(err)
		return nil, nil, err
	}

	/**************************************************************************
	**	Generate an Initialization Vector to perform the CTR AES Encryption
	**************************************************************************/
	IV, err := generateNonce(aes.BlockSize)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, err
	}

	/**************************************************************************
	**	Perform the actual encryption
	**************************************************************************/
	EncryptedPublicKey := make([]byte, len(paddedPublicKey))
	enc := cipher.NewCBCEncrypter(block, IV)
	enc.CryptBlocks(EncryptedPublicKey, paddedPublicKey)

	return EncryptedPublicKey, IV, nil
}
func	DecryptPublicKey(publicKey, IV []byte, secretKey string) ([]byte, error) {
	/**************************************************************************
	**	Decode the master key from hex to string
	**************************************************************************/
	secretKeyHex, err := base64.RawStdEncoding.DecodeString(secretKey)
	if (err != nil) {
		logs.Error(err)
		return nil, err
	}

	/**************************************************************************
	**	Create a Cipher with the master key
	**************************************************************************/
	block, err := aes.NewCipher(secretKeyHex)
	if (err != nil) {
		logs.Error(err)
		return nil, err
	}

	/**************************************************************************
	**	Perform the actual encryption
	**************************************************************************/
	DecryptedPublicKey := make([]byte, len(publicKey))
	enc := cipher.NewCBCDecrypter(block, IV)
	enc.CryptBlocks(DecryptedPublicKey, publicKey)

	/**************************************************************************
	**	Remove padding to the key
	**************************************************************************/
	unPaddedPublicKey, err := pkcs7Unpad(DecryptedPublicKey, block.BlockSize())
	if (err != nil) {
		logs.Error(err)
		return nil, err
	}

	return unPaddedPublicKey, nil
}

/******************************************************************************
**	ENCRYPTION - PEM PRIVATE KEY
**	Use AES to encrypt the PEM private Key with the secret key as symmetric
**	key. Secret key is unknow by server.
******************************************************************************/
func	EncryptPrivateKey(privateKey, secretKey []byte) ([]byte, []byte, []byte, error) {
	salt, hash, _ := GenerateKeyHash(string(secretKey))

	/**************************************************************************
	**	Create a Cipher with the master key
	**************************************************************************/
	block, err := aes.NewCipher([]byte(hash))
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, err
	}

	/**************************************************************************
	**	Generate an Initialization Vector to perform the CTR AES Encryption
	**************************************************************************/
	IV, err := generateNonce(aes.BlockSize)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, err
	}

	/**************************************************************************
	**	Add padding to the key
	**************************************************************************/
	paddedPrivateKey, err := pkcs7Pad(privateKey, block.BlockSize())
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, err
	}

	/**************************************************************************
	**	Perform the actual encryption
	**************************************************************************/
	EncryptedPrivateKey := make([]byte, len(paddedPrivateKey))
	enc := cipher.NewCBCEncrypter(block, IV)
	enc.CryptBlocks(EncryptedPrivateKey, paddedPrivateKey)

	return EncryptedPrivateKey, IV, salt, nil
}
func	DecryptPrivateKey(privateKey, salt, IV, secretKey, secretHash []byte) ([]byte, error) {
	hash := GetHashFromKey(secretKey, salt)

	/**************************************************************************
	**	Create a Cipher with the master key
	**************************************************************************/
	block, err := aes.NewCipher([]byte(hash))
	if (err != nil) {
		logs.Error(err)
		return nil, err
	}

	/**************************************************************************
	**	Perform the actual encryption
	**************************************************************************/
	DecryptedPrivateKey := make([]byte, len(privateKey))
	enc := cipher.NewCBCDecrypter(block, IV)
	enc.CryptBlocks(DecryptedPrivateKey, privateKey)

	/**************************************************************************
	**	Remove padding to the key
	**************************************************************************/
	unPaddedPrivateKey, err := pkcs7Unpad(DecryptedPrivateKey, block.BlockSize())
	if (err != nil) {
		logs.Error(err)
		return nil, err
	}

	block = nil
	DecryptedPrivateKey = nil
	return unPaddedPrivateKey, nil
}