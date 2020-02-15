/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Sunday 05 January 2020 - 22:40:20
** @Filename:				Argon2hash.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Saturday 15 February 2020 - 15:04:54
*******************************************************************************/

package			main

import			"fmt"
import			"crypto/rand"
import			"encoding/base64"
import			"golang.org/x/crypto/argon2"
import			"golang.org/x/crypto/scrypt"
import			"crypto/subtle"
import			"strings"
import			"runtime"

type argon2Params struct {
	memory          uint32
	iterations      uint32
	parallelism     uint8
	saltLength      uint32
	keyLength       uint32
}

func    initArgon2Parameters() (*argon2Params) {
	return &argon2Params{
		memory:      MemoryAmount * 1024,
		iterations:  64 / MemoryAmount,
		parallelism: uint8(runtime.NumCPU()),
		saltLength:  32,
		keyLength:   32,
	}
}
const	MemoryAmount = 32 //Should be 64
var		argon2Parameters = initArgon2Parameters()

func	generateNonce(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if (err != nil) {
		return nil, err
	}
	return b, nil
}

func	generateArgon2HashFromPassword(password string) (encodedHash string, salt, hash []byte, err error) {
	/**************************************************************************
	**  Hash a password with entropy (generateNonce). We can retreive the hash
	**  with the same password as long as the the same params are used, but
	**  we cannot discover the password from the hash
	**************************************************************************/
	salt, err = generateNonce(argon2Parameters.saltLength)
	if (err != nil) {
		return ``, nil, nil, err
	}

	hash = argon2.IDKey([]byte(password), salt, argon2Parameters.iterations, argon2Parameters.memory, argon2Parameters.parallelism, argon2Parameters.keyLength)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	encodedHash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argon2Parameters.memory, argon2Parameters.iterations, argon2Parameters.parallelism, b64Salt, b64Hash)
	return encodedHash, salt, hash, nil
}
func	compareArgon2PasswordAndHash(password, encodedHash string) (match bool, err error) {
	p, salt, hash, err := decodeArgon2Hash(encodedHash)
	if (err != nil) {
		return false, err
	}

	otherHash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	if (subtle.ConstantTimeCompare(hash, otherHash) == 1) {
		return true, nil
	}
	return false, nil
}
func	decodeArgon2Hash(encodedHash string) (p *argon2Params, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if (err != nil) {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = &argon2Params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism)
	if (err != nil) {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.DecodeString(vals[4])
	if (err != nil) {
		return nil, nil, nil, err
	}
	p.saltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.DecodeString(vals[5])
	if (err != nil) {
		return nil, nil, nil, err
	}
	p.keyLength = uint32(len(hash))

	return p, salt, hash, nil
}
func	argon2Match(password, hashedPassword string) (bool) {
	match, err := compareArgon2PasswordAndHash(password, hashedPassword)
	if (err != nil) {
		return (false)
	}
	return (match)
}


func	generateScryptHashFromPassword(password string) (encodedHash string, err error) {
	const	memory = 64 * 1024
	const	r = 8
	const	p = 3
	
	salt, err := generateNonce(32)
	if (err != nil) {
		return ``, err
	}

	hash, err := scrypt.Key([]byte(password), salt, memory, r, p, 32)
	if (err != nil) {
		return ``, err
	}
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	
	encodedHash = fmt.Sprintf("$scrypt$n=%d,r=%d,p=%d$%s$%s", memory, r, p, b64Salt, b64Hash)

	return encodedHash, nil
}
func	decodeScryptHash(encodedHash string) (salt, hash []byte, memory, r, p, keyLen int, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 5 {
		return nil, nil, 0, 0, 0, 0, ErrInvalidHash
	}

	_, err = fmt.Sscanf(vals[2], "n=%d,r=%d,p=%d", &memory, &r, &p)
	if (err != nil) {
		return nil, nil, 0, 0, 0, 0, err
	}

	salt, err = base64.RawStdEncoding.DecodeString(vals[3])
	if (err != nil) {
		return nil, nil, 0, 0, 0, 0, err
	}

	hash, err = base64.RawStdEncoding.DecodeString(vals[4])
	if (err != nil) {
		return nil, nil, 0, 0, 0, 0, err
	}
	keyLen = len(hash)
	
	return
}
func	compareScryptPasswordAndHash(password, encodedHash string) (match bool, err error) {
   salt, hash, memory, r, p, keyLen, err := decodeScryptHash(encodedHash)

	if (err != nil) {
		return false, err
	}

	otherHash, err := scrypt.Key([]byte(password), salt, memory, r, p, keyLen)
	if (err != nil) {
		return false, err
	}
	if (subtle.ConstantTimeCompare(hash, otherHash) == 1) {
		return true, nil
	}
	return false, nil
}
func	scryptMatch(password, hashedPassword string) (bool) {
	match, err := compareScryptPasswordAndHash(password, hashedPassword)
	if (err != nil) {
		return (false)
	}
	return (match)
}

func	hashMemberPassword(password string) ([]byte, []byte, error) {
	encodedArgon2Hash, _, _, err := generateArgon2HashFromPassword(password)
	if (err != nil) {
		return nil, nil, err
	}
	encodedScryptHash, err := generateScryptHashFromPassword(password)
	if (err != nil) {
		return nil, nil, err
	}
	return []byte(encodedArgon2Hash), []byte(encodedScryptHash), nil
}
func    verifyMemberPasswordHash(password, argon2Hash, scryptHash string) (bool) {
	return argon2Match(password, argon2Hash) && scryptMatch(password, scryptHash)
}
