package wxbizdatacrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

var ErrorAppIDNotMatch = errors.New("app id not match")

type UserInfo struct {
	OpenID    string `json:"openId"`
	NickName  string `json:"nickName"`
	Gender    int    `json:"gender"`
	City      string `json:"city"`
	Province  string `json:"province"`
	Country   string `json:"country"`
	AvatarURL string `json:"avatarUrl"`
	Language  string `json:"language"`
	Watermark struct {
		Timestamp int64  `json:"timestamp"`
		AppID     string `json:"appid"`
	} `json:"watermark"`
}

type WXBizDataCrypt struct {
	appID, sessionKey string
}

func NewWXBizDataCrypt(appID, sessionKey string) *WXBizDataCrypt {
	return &WXBizDataCrypt{
		appID:      appID,
		sessionKey: sessionKey,
	}
}

func (w *WXBizDataCrypt) Decrypt(encryptedData, iv string) (*UserInfo, error) {
	aesKey, err := base64.StdEncoding.DecodeString(w.sessionKey)
	if err != nil {
		return nil, err
	}
	cipherText, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}
	ivBytes, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, ivBytes)
	mode.CryptBlocks(cipherText, cipherText)
	cipherText = []byte(strings.Replace(string(cipherText), "\f", "", -1))
	cipherText = []byte(strings.Replace(string(cipherText), "\a", "", -1))
	var userInfo UserInfo
	err = json.Unmarshal(cipherText, &userInfo)
	if err != nil {
		return nil, err
	}
	if userInfo.Watermark.AppID != w.appID {
		return nil, ErrorAppIDNotMatch
	}
	return &userInfo, nil
}
