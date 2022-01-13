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
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/psanford/kmssigner"
)

func main() {
	var err error

	assumeRole := flag.String("assume-role", "", "role ARN to assume")
	region := flag.String("region", "", "region to use")
	arn := flag.String("arn", "", "KMS arn")
	csr := flag.String("csr", "", "Certificate Request file")
	cn := flag.String("cn", "", "Subject CN (if csr not set)")
	ca := flag.String("ca", "", "CA Certificate (if not set, certificate will be self-signed)")
	serial := flag.Uint64("serial", 0, "Serial Number")
	years := flag.Uint("years", 0, "Validity in years")
	duration := flag.Duration("duration", 0, "Validity in 'duration' units")
	pathLen := flag.Int("max-path-len", -1, "Max path length constraint")
	permittedDNSDomains := flag.String("permitted-dns-domains", "", "DNS Name Constraints (comma separated)")
	excludedDNSDomains := flag.String("excluded-dns-domains", "", "DNS Name Constraints (comma separated)")

	test := flag.Bool("test", false, "Test mode (Generate random key)")
	testKey := flag.String("test-key", "", "Test mode (Use .key file for CA)")

	flag.Parse()

	awsSession := session.New(&aws.Config{
		Region: region,
	})

	var kmsClient *kms.KMS
	if *assumeRole != "" {
		creds := stscreds.NewCredentials(awsSession, *assumeRole)
		kmsClient = kms.New(awsSession, &aws.Config{Credentials: creds})
	} else {
		kmsClient = kms.New(awsSession)
	}

	var signer crypto.Signer
	if *testKey != "" {
		testKeyBytes, err := readPEMFile(*testKey)
		if err != nil {
			log.Fatal(err)
		}
		signer, err = x509.ParsePKCS1PrivateKey(testKeyBytes)
	} else if *test {
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
		csrBytes, err := readPEMFile(*csr)
		if err != nil {
			log.Fatal(err)
		}

		request, err = x509.ParseCertificateRequest(csrBytes)
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

	var bigSerial *big.Int
	if *serial != 0 {
		bigSerial = big.NewInt(int64(*serial))
	} else {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		bigSerial, err = rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			log.Fatalf("rand.Int failed: %s", err)
		}
	}

	cert := &x509.Certificate{
		SerialNumber: bigSerial,
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

	if *duration != 0 {
		cert.NotAfter = cert.NotBefore.Add(*duration)
	} else if *years != 0 {
		cert.NotAfter = cert.NotBefore.AddDate(int(*years), 0, 0)
	} else {
		log.Fatal("must set either -years or -duration")
	}

	if *permittedDNSDomains != "" {
		cert.PermittedDNSDomains = strings.Split(*permittedDNSDomains, ",")
		cert.PermittedDNSDomainsCritical = true
	}
	if *excludedDNSDomains != "" {
		cert.ExcludedDNSDomains = strings.Split(*excludedDNSDomains, ",")
	}

	var issuer *x509.Certificate
	if *ca == "" {
		issuer = cert
	} else {
		caBytes, err := readPEMFile(*ca)
		if err != nil {
			log.Fatal(err)
		}

		issuer, err = x509.ParseCertificate(caBytes)
		if err != nil {
			log.Fatalf("x509.ParseCertificate(ca) failed: %s", err)
		}
	}

	signed, err := x509.CreateCertificate(rand.Reader, cert, issuer, cert.PublicKey, signer)
	if err != nil {
		log.Fatalf("x509.CreateCertificate failed: %s", err)
	}

	pemOut := &pem.Block{Type: "CERTIFICATE", Bytes: signed}
	err = pem.Encode(os.Stdout, pemOut)
	if err != nil {
		log.Fatalf("pem.Encode failed: %s", err)
	}

	if *test && *testKey == "" {
		pem.Encode(os.Stdout,
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(signer.(*rsa.PrivateKey)),
			},
		)
	}
}

func readPEMFile(file string) ([]byte, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("os.ReadFile(%s) failed: %w", file, err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("pem.Decode(%s) failed", file)
	}

	return block.Bytes, nil
}
