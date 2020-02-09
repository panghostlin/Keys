/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Monday 06 January 2020 - 13:29:25
** @Filename:				SymmetricEncryption.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Tuesday 28 January 2020 - 21:58:49
*******************************************************************************/

package			main

// import			"fmt"
import			"strings"
import			"github.com/microgolang/logs"
import			"crypto/aes"
import			"crypto/cipher"
import			"encoding/base64"

/******************************************************************************
**	ENCRYPTION - Random Element
**	Use AES to encrypt the PEM private Key with the secret key as symmetric
**	key. Secret key is unknow by server.
******************************************************************************/
func	EncryptData(data []byte) ([]byte, []byte, []byte, error) {
	secretKey, _ := generateNonce(32)

	/**************************************************************************
	**	Create a Cipher with the master key
	**************************************************************************/
	block, err := aes.NewCipher(secretKey)
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
	paddedData, err := pkcs7Pad(data, block.BlockSize())
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, err
	}

	/**************************************************************************
	**	Perform the actual encryption
	**************************************************************************/
	EncryptedData := make([]byte, len(paddedData))
	enc := cipher.NewCBCEncrypter(block, IV)
	enc.CryptBlocks(EncryptedData, paddedData)

	return EncryptedData, IV, secretKey, nil
}
func	DecryptData(data, IV, secretKey []byte) ([]byte, error) {
	/**************************************************************************
	**	Create a Cipher with the master key
	**************************************************************************/
	block, err := aes.NewCipher(secretKey)
	if (err != nil) {
		logs.Error(err)
		return nil, err
	}

	/**************************************************************************
	**	Perform the actual encryption
	**************************************************************************/
	DecryptedData := make([]byte, len(data))
	enc := cipher.NewCBCDecrypter(block, IV)
	enc.CryptBlocks(DecryptedData, data)

	/**************************************************************************
	**	Remove padding to the key
	**************************************************************************/
	unPaddedData, err := pkcs7Unpad(DecryptedData, block.BlockSize())
	if (err != nil) {
		logs.Error(err)
		return nil, err
	}

	return unPaddedData, nil
}
func	DecodeCipherKey(secretKey string) ([]byte, []byte, error) {
    vals := strings.Split(secretKey, "$")

	if (len(vals) != 3) {
        return nil, nil, ErrInvalidHash
    }

    ciphertext, err := base64.RawStdEncoding.DecodeString(vals[1])
    if (err != nil) {
        return nil, nil, err
    }

    IV, err := base64.RawStdEncoding.DecodeString(vals[2])
    if (err != nil) {
        return nil, nil, err
	}

	return ciphertext, IV, nil
}