package basiccrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/hex"
	"io"
	"strings"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

// Encrypt is delegated to crypt the data in input with the given password
func Encrypt(data []byte, passphrase string) string {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return b64.StdEncoding.EncodeToString(ciphertext)
}

func createHash(key string) string {
	hasher := md5.New()
	if _, err := hasher.Write([]byte(key)); err != nil {
		return ""
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func decrypt(data, passphrase string) string {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	raw, err1 := b64.StdEncoding.DecodeString(data)
	if err1 != nil {
		panic(err1.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Error("Error during decrypt: ", err)
		panic(err.Error())
	}
	return string(plaintext)
}

// GenerateToken create a token for authenticate the request
func GenerateToken(username string, password string) string {
	return Encrypt([]byte(username+":"+password), password)
}

func verifyTokens(token1, token2, password string) bool {
	decrypted1 := decrypt(token1, password)
	log.Debug("VerifyTokens | First token decrypted [", token1, " -> ", decrypted1, "]")
	decrypted2 := decrypt(token2, password)
	logrus.Debug("VerifyTokens | First token decrypted [", token2, " -> ", decrypted2, "]")
	return strings.Compare(decrypted1, decrypted2) == 0
}

// VerifyPlainPasswords is delegated to verify if the incoming password is equals to the one stored in the DB
func VerifyPlainPasswords(plainPswUser, chiperPswDb, key string) bool {
	log.Debug("VerifyPlainPasswords | Verifying if ["+plainPswUser+"] belong to [", chiperPswDb, "]")
	plainDb := decrypt(chiperPswDb, key)
	log.Debug("VerifyPlainPasswords | Plain DB: ", plainDb)
	return strings.Compare(plainPswUser, plainDb) == 0
}
