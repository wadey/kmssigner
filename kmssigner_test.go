package kmssigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func TestKmsSignerRSA(t *testing.T) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		t.Skip("AWS_REGION not set, skipping")
		return
	}

	rsaKeyARN := os.Getenv("KMS_TEST_KEY_ID_RSA_ARN")
	if rsaKeyARN == "" {
		t.Skip("KMS_TEST_KEY_ID_RSA_ARN not set, skipping")
		return
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
	)
	if err != nil {
		t.Fatal(err)
	}

	kmsClient := kms.NewFromConfig(cfg)

	signer, err := New(kmsClient, rsaKeyARN)
	if err != nil {
		t.Fatal(err)
	}

	msg := "highlights-Dadaism"

	hashers := []struct {
		h hash.Hash
		t crypto.Hash
	}{
		{sha256.New(), crypto.SHA256},
		{sha512.New384(), crypto.SHA384},
		{sha512.New(), crypto.SHA512},
	}

	pubKey := signer.Public().(*rsa.PublicKey)

	for _, hasher := range hashers {
		fmt.Fprint(hasher.h, msg)
		sum := hasher.h.Sum(nil)

		sig, err := signer.Sign(rand.Reader, sum, hasher.t)
		if err != nil {
			t.Errorf("digest err for %s: %s", hasher.t, err)
			continue
		}

		err = rsa.VerifyPKCS1v15(pubKey, hasher.t, sum, sig)
		if err != nil {
			t.Errorf("verify failed for rsa pkcs1v15 %s: %s", hasher.t, err)
		}
	}
}

func TestKmsSignerP256(t *testing.T) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		t.Skip("AWS_REGION not set, skipping")
		return
	}

	p256KeyARN := os.Getenv("KMS_TEST_KEY_ID_P256_ARN")
	if p256KeyARN == "" {
		t.Skip("KMS_TEST_KEY_ID_P256_ARN not set, skipping")
		return
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
	)
	if err != nil {
		t.Fatal(err)
	}

	kmsClient := kms.NewFromConfig(cfg)

	signer, err := New(kmsClient, p256KeyARN)
	if err != nil {
		t.Fatal(err)
	}

	msg := "subsistence-gunfight"

	hashers := []struct {
		h hash.Hash
		t crypto.Hash
	}{
		{sha256.New(), crypto.SHA256},
	}

	pubKey := signer.Public().(*ecdsa.PublicKey)

	for _, hasher := range hashers {
		fmt.Fprint(hasher.h, msg)
		sum := hasher.h.Sum(nil)

		sig, err := signer.Sign(rand.Reader, sum, hasher.t)
		if err != nil {
			t.Errorf("digest err for %s: %s", hasher.t, err)
			continue
		}

		ok := ecdsa.VerifyASN1(pubKey, sum, sig)
		if !ok {
			t.Errorf("verify failed for ecc p256 %s", hasher.t)
		}
	}
}
