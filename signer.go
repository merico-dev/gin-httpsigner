package gin_httpsigner

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/merico-dev/httpsign"
)

const (
	authorizationHeaderKey = "Authorization"
	signatureHeaderKey     = "Signature"
	dateHeaderKey          = "date"
	timestampHeaderKey     = "timestamp"
	digestHeaderKey        = "digest"
	requestTarget          = "(request-target)"
	host                   = "host"
)

// SignatureHeader contains basic info signature header
type SignatureHeader struct {
	keyID     httpsign.KeyID
	headers   []string
	signature string
	algorithm string
}

func (s *SignatureHeader) String() string {
	return fmt.Sprintf(
		"Signature keyId=\"%s\",algorithm=\"%s\",headers=\"%s\",signature=\"%s\"",
		s.keyID, s.algorithm, strings.Join(s.headers, " "), s.signature,
	)
}

type GinHttpSigner struct {
	keyId   httpsign.KeyID
	secret  *httpsign.Secret
	headers []string
}

func NewGinHttpSigner(keyId httpsign.KeyID, secret *httpsign.Secret, headers []string) *GinHttpSigner {
	ginHttpSigner := &GinHttpSigner{
		keyId:   keyId,
		secret:  secret,
		headers: []string{dateHeaderKey, digestHeaderKey, requestTarget},
	}
	if len(headers) != 0 {
		ginHttpSigner.headers = headers
	}
	return ginHttpSigner
}

func (singer *GinHttpSigner) GetSignatureHeader(signatureBase64 string) (*SignatureHeader, error) {
	return &SignatureHeader{
		keyID:     singer.keyId,
		headers:   singer.headers,
		signature: signatureBase64,
		algorithm: singer.secret.Algorithm.Name(),
	}, nil
}

func (singer *GinHttpSigner) SignRequest(req *http.Request) error {
	if err := singer.setDate(req); err != nil {
		return err
	}
	if err := singer.setDigest(req); err != nil {
		return err
	}
	if err := singer.setAuth(req); err != nil {
		return err
	}
	return nil
}

func (singer *GinHttpSigner) setAuth(req *http.Request) error {
	signString := constructSignMessage(req, singer.headers)
	signature, err := singer.secret.Algorithm.Sign(signString, singer.secret.Key)
	if err != nil {
		return err
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	signatureHeader, err := singer.GetSignatureHeader(signatureBase64)
	if err != nil {
		return err
	}
	req.Header.Set(authorizationHeaderKey, signatureHeader.String())
	return nil
}

func (singer *GinHttpSigner) setDate(req *http.Request) error {
	req.Header.Set(dateHeaderKey, fmt.Sprintf("%d", time.Now().Unix()))
	return nil
}

func (singer *GinHttpSigner) setDigest(req *http.Request) error {
	digest, err := calculateDigest(req)
	if err != nil {
		return err
	}
	req.Header.Set(digestHeaderKey, digest)
	return nil
}

func calculateDigest(r *http.Request) (string, error) {
	if r.ContentLength == 0 {
		return "", nil
	}
	// TODO: Read body using buffer to prevent using too much memory
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	h := sha256.New()
	h.Write(body)
	if err != nil {
		return "", err
	}
	digest := fmt.Sprintf("SHA-256=%s", base64.StdEncoding.EncodeToString(h.Sum(nil)))
	return digest, nil
}

func constructSignMessage(r *http.Request, headers []string) string {
	var signBuffer bytes.Buffer
	for i, field := range headers {
		var fieldValue string
		switch field {
		case host:
			fieldValue = r.Host
		case requestTarget:
			fieldValue = fmt.Sprintf("%s %s", strings.ToLower(r.Method), r.URL.RequestURI())
		default:
			fieldValue = r.Header.Get(field)
		}
		signString := fmt.Sprintf("%s: %s", field, fieldValue)
		signBuffer.WriteString(signString)
		if i < len(headers)-1 {
			signBuffer.WriteString("\n")
		}
	}
	return signBuffer.String()
}
