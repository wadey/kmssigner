# Go crypto.Signer impl for AWS KMS keys

This is an implementation of crypto.Signer using AWS KMS APIs. This might be useful if you need to ensure your keys are protected by an HSM and that all access gets logged (via cloudtrail).
