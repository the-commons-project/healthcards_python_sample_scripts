#!/usr/bin/env python
from jwcrypto import jwk
import argparse
import json


def generate_signing_key():
    key = jwk.JWK.generate(kty='EC', crv='P-256', alg='ES256', use='sig')
    key._params['kid'] = key.thumbprint()
    return key


def generate_encryption_key():
    key = jwk.JWK.generate(kty='EC', crv='P-256', alg='ECDH-ES', use='enc')
    key._params['kid'] = key.thumbprint()
    return key


def generate_keyset(keys):
    keyset = jwk.JWKSet()
    for key in keys:
        keyset.add(key)
    return keyset


def main():

    parser = argparse.ArgumentParser(description='Generates a random JWK set')
    parser.add_argument('public_file', help='Public JWKS Output file')
    parser.add_argument('private_file', help='Private Key Output file')

    private_signing_key = generate_signing_key()
    private_encryption_key = generate_encryption_key()

    keyset = generate_keyset([private_signing_key, private_encryption_key])

    args = parser.parse_args()
    with open(args.private_file, 'w', newline='') as private_file:
        json.dump(keyset.export(private_keys=True, as_dict=True), private_file, indent=4)
    with open(args.public_file, 'w', newline='') as public_file:
        json.dump(keyset.export(private_keys=False, as_dict=True), public_file, indent=4)


if __name__ == "__main__":
    main()
