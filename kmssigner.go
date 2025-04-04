package kmssigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type signer struct {
	kms    KMSAPI
	keyARN string
	pubKey crypto.PublicKey
}

// KMS is an interface with only the methods we care about from *kms.Client
// This allows the caller to give us a mock, etc.
type KMSAPI interface {
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

func New(kapi KMSAPI, keyARN string) (crypto.Signer, error) {
	kout, err := kapi.GetPublicKey(context.TODO(), &kms.GetPublicKeyInput{
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

	output, err := s.kms.Sign(context.TODO(), &kms.SignInput{
		KeyId:            &s.keyARN,
		SigningAlgorithm: types.SigningAlgorithmSpec(modePrefix + modeSuffix),
		MessageType:      types.MessageTypeDigest,
		Message:          digest,
	})
	if err != nil {
		return nil, err
	}

	return output.Signature, nil
}

// GetSigner returns a function which signs the given bytes using
// the given kms.Client and the key at the given arn and returns the signature.
// If verify is true, then the signature is verified using the public key.
func GetSigner(client *kms.Client, arn string, verify bool) (func([]byte) ([]byte, error), error) {
	const hashFunc = crypto.SHA256
	cs, err := New(client, arn)
	if err != nil {
		return nil, err
	}
	pubkey, ok := cs.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected type *ecdsa.PublicKey but got %T", cs.Public())
	}
	return func(tbs []byte) ([]byte, error) {
		h := hashFunc.New()
		h.Write(tbs)
		digest := h.Sum(nil)

		signature, err := cs.Sign(nil, digest, hashFunc)
		if err != nil {
			return nil, err
		}

		// Check the signature to ensure the crypto.Signer behaved correctly.
		if verify && !ecdsa.VerifyASN1(pubkey, digest, signature) {
			return nil, fmt.Errorf("signature returned by signer is invalid")
		}

		return signature, err
	}, nil
}
