package main

import (
	"crypto"
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
	years := flag.Int("years", 1, "Validity in years")
	flag.Parse()

	awsSession := session.New(&aws.Config{
		Region: region,
	})

	kmsClient := kms.New(awsSession)

	var signer crypto.Signer
	if *arn == "" {
		// For testing
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

		request, err = x509.ParseCertificateRequest(csrBytes)
		if err != nil {
			log.Fatalf("x509.ParseCertificateRequest failed: %s", err)
		}
	} else {
		request = &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: *cn,
			},
			PublicKey:          signer.Public(),
			PublicKeyAlgorithm: x509.RSA, // TODO
		}
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
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
	}
	cert.NotAfter = cert.NotBefore.Add(time.Hour * 8760 * time.Duration(*years))

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
}
