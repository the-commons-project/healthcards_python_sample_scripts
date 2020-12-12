from jwcrypto import jwk, jws, jwe
from jwcrypto.common import json_encode
import argparse
import json
from did.did_service import DIDService
import time
import secrets
from jwcrypto.common import base64url_encode, base64url_decode
import requests
import base64

did_service = DIDService()

def fetch_transform_request(transform_request_uri):
    r = requests.get(transform_request_uri)
    jws_raw = r.text

    ##instantiate a JWS object
    jwstoken = jws.JWS()

    ##import the data into the JWS object
    jwstoken.deserialize(jws_raw)

    ##based on the JWS header, resolve the public signing key to be used for verification
    kid = jwstoken.jose_header.get('kid')
    key = did_service.resolve_key(kid)
    
    ##load the JWK into a useable key
    verifier_key = jwk.JWK.from_json(json.dumps(key))

    ##verify the payload
    jwstoken.verify(verifier_key)

    ##extract the payload
    return json.loads(jwstoken.payload)

def submit_transform(siop_request, encoded_response):
    response_uri = siop_request['client_id']
    response_body = {
        'id_token': encoded_response 
    }
    if 'state' in siop_request:
        response_body['state'] = siop_request['state']

    r = requests.post(response_uri, data=response_body)
    r.raise_for_status()
    return r.json()

def encode_response(payload, did_long_identifier, private_signing_key, signing_key_name):

    ##create a jws token from the payload
    jwstoken = jws.JWS(json.dumps(payload).encode('utf-8'))

    ## sign the token, specifying the kid as concatenation of the did long identifier and the signing key name
    ## this will be used to resolve the signing key by the holder / verifier
    jwstoken.add_signature(
        private_signing_key, 
        None,
        json_encode({"alg": "ES256K", "typ": 'JWT', "kid": f'{did_long_identifier}#{signing_key_name}'})
    )

    ## return the jws as a string
    return jwstoken.serialize(compact=True)

def create_transform_response_payload(transform_request, did, vcs):
    # print(json.dumps(transform_request, indent=4))
    iat = int(time.time())
    exp = iat + 300

    with open('./fixtures/transform-response-payload.json', 'r') as input_file:
        response_payload = json.load(input_file)
        response_payload['did'] = did
        response_payload['aud'] = transform_request['client_id']
        response_payload['nonce'] = secrets.token_urlsafe(16)
        response_payload['iat'] = iat
        response_payload['exp'] = exp
        response_payload['vp']['verifiableCredential'] = vcs

        # print(json.dumps(response_payload, indent=4))

        return response_payload

def decode_vc(jws_raw):
    ##instantiate a JWS object
    jwstoken = jws.JWS()

    ##import the data into the JWS object
    jwstoken.deserialize(jws_raw)

    ##based on the JWS header, resolve the public signing key to be used for verification
    kid = jwstoken.jose_header.get('kid')
    key = did_service.resolve_key(kid)
    
    ##load the JWK into a useable key
    verifier_key = jwk.JWK.from_json(json.dumps(key))

    ##verify the payload
    jwstoken.verify(verifier_key)
    return jwstoken

def process_response(response):

    vcs = []
    for parameter in response['parameter']:
        if parameter['name'] == 'verifiableCredential' and 'valueAttachment' in parameter:
            data = parameter['valueAttachment']['data'].encode('utf-8')
            decoded_data = base64.b64decode(data)
            vcs.append(decoded_data.decode('utf-8'))

    return vcs



def main():
    parser = argparse.ArgumentParser(description='Transforms a vc')
    parser.add_argument('config_file', help='Config file')
    parser.add_argument('input_file', help='Sample VCs to respond with')
    parser.add_argument('output_file', help='Location of output VCs')

    args = parser.parse_args()
    with open(args.config_file, 'r', newline='') as config_file:
        config = json.load(config_file)

    did_long_identifier = config['did_long_identifier']
    did_short_identifier = config['did_short_identifier']

    ## jwk.JWK.from_json requires JSON string
    private_signing_key_json = json.dumps(config['signing_key'])
    private_signing_key = jwk.JWK.from_json(private_signing_key_json)
    signing_key_name = config['signing_key_name']
    transform_request_uri = config['transform_request_uri']

    ##fetch SIOP request for transform
    transform_siop_request = fetch_transform_request(transform_request_uri)

    with open(args.input_file, 'r', newline='') as input_file:
        vcs = json.load(input_file).get('verifiableCredential')
        response_payload = create_transform_response_payload(
            transform_siop_request,
            did_long_identifier,
            vcs
        )

        signed_response = encode_response(
            response_payload,
            did_long_identifier,
            private_signing_key,
            signing_key_name
        )

        transform_response = submit_transform(
            transform_siop_request,
            signed_response
        )

        vcs = process_response(transform_response)
        decoded_vcs = [decode_vc(vc) for vc in vcs]

        ## this is the general format for a FHIR backed vc file, this is subject to change
        with open(args.output_file, 'w') as outfile:
            output_dict = {
                'verifiableCredential': vcs
            }
            json.dump(output_dict, outfile)
        
if __name__ == "__main__":
    main()