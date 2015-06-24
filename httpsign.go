// Package httpsign provides HTTP Middleware for signing and verifying
// HMAC SHA256 signatures for trusting the source of a request
package httpsign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// GetValue is a type of function to pass `SignToProxy` and `Verify` to return
// whatever content you wish to include in the calcuation of signature. This
// must be agreed upon by both parties.
type GetValue func(w http.ResponseWriter, r *http.Request) string

// A function to call for logging problems, currently only used in Verify().
type LogHook func(r *http.Request, msg string)

// HttpSign is the main package object
type HttpSign struct {
	HeaderName       string
	SecondsAllowance int
	Key              []byte
	DisableVerify    bool // Supports testing by disabling the checking in Verify()
	LogHook          LogHook
}

// New returns a pointer to a HttpSign object configured with the key and with
// the package defaults.
func New(key []byte) *HttpSign {
	httpSign := HttpSign{
		HeaderName:       "X-Signature",
		SecondsAllowance: 6,
		Key:              key,
	}
	return &httpSign
}

func (hs *HttpSign) log(r *http.Request, msgPattern string, args ...interface{}) {
	if hs.LogHook != nil {
		hs.LogHook(r, fmt.Sprintf(msgPattern, args...))
	}
}

// SignToProxy is HTTP middleware intended to be used by a proxy server that
// receives requests, appends headers and then proxies the request copying
// the original and appended headers. This can be used with
// [Oxy](https://github.com/mailgun/oxy)
func (hs *HttpSign) SignToProxy(h http.Handler, v GetValue) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := v(w, r)
		epoch := time.Now().Unix()
		signature := calcHMAC(hs.Key, value, epoch)
		r.Header.Add(hs.HeaderName, formHeader(signature, epoch))
		h.ServeHTTP(w, r)
	})
}

// Verify is HTTP middleware for veryify the signature of a received signed
// request. Both parties must agree on the HTTP Header and content used to
// calculate the signature.
//
// Verify will respond with a `400` response if the signature is invalid.
// Otherwise it will call the next middleware in the chain.
func (hs *HttpSign) Verify(h http.Handler, v GetValue) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get(hs.HeaderName)
		if hs.DisableVerify {
			h.ServeHTTP(w, r)
			return
		}
		expectedSignature, expectedEpoch, err := parseHeader(header)
		if err != nil {
			hs.log(r, "Unable to parse header '%s'", header)
			hs.writeInvalid(w)
			return
		}
		now := time.Now().Unix()
		if now > expectedEpoch+int64(hs.SecondsAllowance) {
			hs.log(r, "Stale timestamp %d (now=%d, allowance=%d)", expectedEpoch, now, hs.SecondsAllowance)
			hs.writeInvalid(w)
			return
		}

		value := v(w, r)
		signature := calcHMAC(hs.Key, value, expectedEpoch)

		if signature != expectedSignature {
			hs.log(r, "Signature mismatch %s (calculated=%s, header=%s)", expectedSignature, signature, header)
			hs.writeInvalid(w)
			return
		}

		h.ServeHTTP(w, r)
	})
}

// GenerateHeaderValue takes a content string, calculates an HMAC and returns
// a properly formated header value including the epoch timestamp
func (hs *HttpSign) GenerateHeaderValue(value string) string {
	epoch := time.Now().Unix()
	signature := calcHMAC(hs.Key, value, epoch)
	header := formHeader(signature, epoch)
	return header
}

func (hs *HttpSign) writeInvalid(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(hs.HeaderName + " invalid"))
}

func calcHMAC(key []byte, value string, epoch int64) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(formMessage(value, epoch))
	signature := mac.Sum(nil)
	return string(signature)
}

func formMessage(value string, epoch int64) []byte {
	return []byte(fmt.Sprintf("%s%d", value, epoch))
}

func formHeader(signature string, epoch int64) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(signature))
	return fmt.Sprintf("%s;%d", b64, epoch)
}

func parseHeader(h string) (signature string, epoch int64, err error) {
	parts := strings.Split(h, ";")
	if len(parts) != 2 {
		err = fmt.Errorf("Invalid header format")
		return
	}
	b, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return
	}
	signature = string(b)
	epoch, err = strconv.ParseInt(parts[1], 10, 64)
	return
}
