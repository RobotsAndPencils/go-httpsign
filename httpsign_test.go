package httpsign

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseHeader(t *testing.T) {
	assert := assert.New(t)
	val := randomString(25)
	expectedEpoch := time.Now().Unix()
	expectedSignature := fmt.Sprintf("%s%d", val, expectedEpoch)
	encodedSignature := base64.StdEncoding.EncodeToString([]byte(expectedSignature))
	header := fmt.Sprintf("%s;%d", encodedSignature, expectedEpoch)
	signature, epoch, err := parseHeader(header)
	assert.NoError(err)
	assert.Equal(expectedSignature, signature)
	assert.Equal(expectedEpoch, epoch)
}

func TestFormHeader(t *testing.T) {
	assert := assert.New(t)
	value := randomString(25)
	key := []byte(randomString(100))
	signature := calcHMAC(key, value)
	epoch := time.Now().Unix()

	encodedSignature := base64.StdEncoding.EncodeToString([]byte(signature))
	expectedHeader := fmt.Sprintf("%s;%d", encodedSignature, epoch)
	header := formHeader(signature, epoch)
	assert.Equal(expectedHeader, header)
}

func TestGenerateHeaderValue(t *testing.T) {
	assert := assert.New(t)
	value := randomString(25)
	key := []byte(randomString(100))
	hs := New(key)
	signature := calcHMAC(key, value)
	epoch := time.Now().Unix()
	expectedHeader := formHeader(signature, epoch)
	header := hs.GenerateHeaderValue(value)
	assert.Equal(expectedHeader, header)
}

func TestSignToProxy(t *testing.T) {
	assert := assert.New(t)
	value := randomString(25)
	key := []byte(randomString(100))
	hs := New(key)
	signature := calcHMAC(key, value)
	epoch := time.Now().Unix()
	expectedHeader := formHeader(signature, epoch)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// handle time race condidition if we are right on the second boundary
		if epoch != time.Now().Unix() {
			expectedHeader = formHeader(signature, epoch)
		}

		h := r.Header.Get(hs.HeaderName)
		fmt.Println(h)
		assert.Equal(expectedHeader, h)

		s, e, err := parseHeader(h)
		assert.NoError(err)
		assert.Equal(signature, s)
		assert.True(time.Now().Unix() < e+int64(6))
		w.WriteHeader(http.StatusOK)
	})

	v := func(w http.ResponseWriter, r *http.Request) string {
		return value
	}

	ts := httptest.NewServer(hs.SignToProxy(h, v))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL, nil)
	assert.Nil(err)
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()
	assert.Equal(http.StatusOK, resp.StatusCode)
}

func TestVerify(t *testing.T) {
	assert := assert.New(t)
	value := randomString(25)
	key := []byte(randomString(100))
	hs := New(key)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	v := func(w http.ResponseWriter, r *http.Request) string {
		return value
	}

	ts := httptest.NewServer(hs.Verify(h, v))
	defer ts.Close()

	// make request with no header
	req, err := http.NewRequest("GET", ts.URL, nil)
	assert.Nil(err)
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()
	assert.Equal(http.StatusBadRequest, resp.StatusCode)

	header := hs.GenerateHeaderValue(value)
	req, err = http.NewRequest("GET", ts.URL, nil)
	assert.Nil(err)
	req.Header.Set(hs.HeaderName, header)
	resp, err = http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()
	assert.Equal(http.StatusOK, resp.StatusCode)

}

func randomString(size int) string {
	alphanum := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, size)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}
