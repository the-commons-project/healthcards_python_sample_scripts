from jwcrypto import jwk
import argparse
import json
from did.did_service import DIDService

SigningKeyName = "signing-key-1"
ECEncryptionKeyName = "encryption-key-1"

did_service = DIDService()

def generate_signing_key():
    return jwk.JWK.generate(kty='EC', crv='P-256', alg='ES256')

def generate_encryption_key():
    return jwk.JWK.generate(kty='EC', crv='P-256', alg='ECDH-ES')


def main():

    private_signing_key = generate_signing_key()
    public_signing_key_dict = private_signing_key.export_public(as_dict=True)

    private_encryption_key = generate_encryption_key()
    public_encryption_key_dict = private_encryption_key.export_public(as_dict=True)

    private_update_key = generate_signing_key()
    public_update_key_dict = private_update_key.export_public(as_dict=True)

    private_recovery_key = generate_signing_key()
    public_recovery_key_dict = private_recovery_key.export_public(as_dict=True)

    did = did_service.create_did(
        SigningKeyName,
        public_signing_key_dict,
        ECEncryptionKeyName,
        public_encryption_key_dict,
        public_update_key_dict,
        public_recovery_key_dict
    )

    parser = argparse.ArgumentParser(description='Generates a random DID')
    parser.add_argument('output_file', help='Output file')

    args = parser.parse_args()
    with open(args.output_file, 'w', newline='') as output_file:

        output = {
            'did_short_identifier': did.shortIdentifier,
            'did_initial_state': did.initialState,
            'did_long_identifier': did.longIdentifier,
            'signing_key': private_signing_key.export(as_dict=True),
            'signing_key_json_string': json.dumps(private_signing_key.export(as_dict=True)),
            'signing_key_name': SigningKeyName,
            'encryption_key': private_encryption_key.export(as_dict=True),
            'encryption_key_json_string': json.dumps(private_encryption_key.export(as_dict=True)),
            'encryption_key_name': ECEncryptionKeyName,
            'update_key': private_update_key.export(as_dict=True),
            'recovery_key': private_recovery_key.export(as_dict=True)
        }

        json.dump(output, output_file, indent=4)

if __name__ == "__main__":
    main()
