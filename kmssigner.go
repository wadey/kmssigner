package kmssigner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

type signer struct {
	kms    kmsiface.KMSAPI
	keyARN string
	pubKey crypto.PublicKey
}

func New(kapi kmsiface.KMSAPI, keyARN string) (crypto.Signer, error) {
	kout, err := kapi.GetPublicKey(&kms.GetPublicKeyInput{
		KeyId: &keyARN,
	})
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(kout.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key err: %w", err)
	}

	return &signer{
		kms:    kapi,
		keyARN: keyARN,
		pubKey: pubKey,
	}, nil
}

func (s *signer) Public() crypto.PublicKey {
	return s.pubKey
}

func (s *signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	var (
		modePrefix string
		modeSuffix string
	)

	switch s.pubKey.(type) {
	case *rsa.PublicKey:
		modePrefix = "RSASSA_PKCS1_V1_5_"
	case *ecdsa.PublicKey:
		modePrefix = "ECDSA_"
	default:
	}

	switch opts.HashFunc() {
	case crypto.SHA256:
		modeSuffix = "SHA_256"
	case crypto.SHA384:
		modeSuffix = "SHA_384"
	case crypto.SHA512:
		modeSuffix = "SHA_512"
	}

	output, err := s.kms.Sign(&kms.SignInput{
		KeyId:            &s.keyARN,
		SigningAlgorithm: aws.String(modePrefix + modeSuffix),
		MessageType:      aws.String(kms.MessageTypeDigest),
		Message:          digest,
	})
	if err != nil {
		return nil, err
	}

	return output.Signature, nil
}
