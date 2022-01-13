package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/psanford/kmssigner"
)

func main() {
	var err error

	region := flag.String("region", "", "region to use")
	arn := flag.String("arn", "", "KMS arn")
	csr := flag.String("csr", "", "Certificate Request file")
	cn := flag.String("cn", "", "Subject CN (if csr not set)")
	ca := flag.String("ca", "", "CA Certificate (if not set, certificate will be self-signed)")
	serial := flag.Uint64("serial", 1, "Serial Number")
	years := flag.Uint("years", 1, "Validity in years")
	pathLen := flag.Int("max-path-len", -1, "Max path length constraint")
	test := flag.Bool("test", false, "Test or dry-run mode (don't use KMS)")

	flag.Parse()

	awsSession := session.New(&aws.Config{
		Region: region,
	})

	kmsClient := kms.New(awsSession)

	var signer crypto.Signer
	if *test {
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("rsa.GenerateKey failed: %s", err)
		}
	} else {
		signer, err = kmssigner.New(kmsClient, *arn)
		if err != nil {
			log.Fatalf("kmssigner.New failed: %s", err)
		}
	}

	var request *x509.CertificateRequest
	if *csr != "" {
		csrBytes, err := os.ReadFile(*csr)
		if err != nil {
			log.Fatalf("os.ReadFile(csr) failed: %s", err)
		}

		block, _ := pem.Decode(csrBytes)
		if err != nil {
			log.Fatalf("pem.Decode(csr) failed: %s", err)
		}

		request, err = x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			log.Fatalf("x509.ParseCertificateRequest failed: %s", err)
		}
	} else {
		pub := signer.Public()
		request = &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: *cn,
			},
			PublicKey: pub,
		}
		switch pub.(type) {
		case *rsa.PublicKey:
			request.PublicKeyAlgorithm = x509.RSA
		case *ecdsa.PublicKey:
			request.PublicKeyAlgorithm = x509.ECDSA
		default:
			log.Fatalf("unsupported public key type: %T", pub)
		}
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(int64(*serial)),
		NotBefore:    time.Now(),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCRLSign | x509.KeyUsageCertSign,

		PublicKey:          request.PublicKey,
		PublicKeyAlgorithm: request.PublicKeyAlgorithm,

		Subject:         request.Subject,
		DNSNames:        request.DNSNames,
		EmailAddresses:  request.EmailAddresses,
		IPAddresses:     request.IPAddresses,
		URIs:            request.URIs,
		Extensions:      request.Extensions,
		ExtraExtensions: request.ExtraExtensions,

		BasicConstraintsValid: true,
		MaxPathLen:            *pathLen,
		MaxPathLenZero:        *pathLen == 0,
	}
	cert.NotAfter = cert.NotBefore.AddDate(int(*years), 0, 0)

	var issuer *x509.Certificate
	if *ca == "" {
		issuer = cert
	} else {
		caBytes, err := os.ReadFile(*ca)
		if err != nil {
			log.Fatalf("os.ReadFile(ca) failed: %s", err)
		}

		issuer, err = x509.ParseCertificate(caBytes)
		if err != nil {
			log.Fatalf("x509.ParseCertificate(ca) failed: %s", err)
		}
	}

	signed, err := x509.CreateCertificate(rand.Reader, cert, issuer, signer.Public(), signer)
	if err != nil {
		log.Fatalf("x509.CreateCertificate failed: %s", err)
	}

	pemOut := &pem.Block{Type: "CERTIFICATE", Bytes: signed}
	err = pem.Encode(os.Stdout, pemOut)
	if err != nil {
		log.Fatalf("pem.Encode failed: %s", err)
	}

	if *test {
		pem.Encode(os.Stdout,
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(signer.(*rsa.PrivateKey)),
			},
		)
	}
}
