# HealthCards Sample Scripts for Python

## Installation

Run the `install.sh` script in this directory. 

```
./install.sh
```

The install script takes care of setting up your virtual environment, installing dependencies, etc.

## Activating your Virtual Environment
Before you can run scripts, you must first activate your virtual environment. You can do this with the following command:

```
source myenv/bin/activate
```

## Generate a JWK Set
To generate a random JWK Set, use the following command:

```
python generate_random_jwks.py jwks.json jwks_private.json
```

This script will generate the necessary JWK formatted keys, saving the public keyset in `jwks.json` and the private keyset in `jwks_private.json`.

## Generate a VC
To generate a sample VC, use the following command:

```
python encode_resource.py jwks_private.json https://commonhealth.org fixtures/vc-c19-pcr-jwt-payload.json sample_vcs/lab_result.smart-health-card
```

This script uses the private JWK set defined in `jwks_private.json`, generates a new VC based on `./fixtures/vc-c19-pcr-jwt-payload.json`, and saves that in `sample_vcs/lab_result.smart-health-card`.

## Verify a VC
To verifiy a VC, use the following command:

```
python decode_resource.py sample_vcs/covid19.smart-health-card  
```

This script loads the VC from `sample_vcs/covid19.smart-health-card`, and verifies it based on the issuer and kid information encoded in the JWS.

## Testing locally

You can run a local server to serve .well-known/jwks.json.

Use the following commands:

```
python generate_random_jwks.py .well-known/jwks.json jwks_private.json
python encode_resource.py jwks_private.json http://localhost:8080 fixtures/vc-c19-pcr-jwt-payload.json sample_vcs/lab_result.smart-health-card
```

Then, start running a local server:

```
python -m http.server 8080
```

Finally, verify the VC using the following command:
```
python decode_resource.py sample_vcs/lab_result.smart-health-card
```

Additionally, you can test QR code generation with the sample QR code scanning app and a locally running verifier service using the following command to generate a QR code:

```
python encode_resource_in_qr_code.py jwks_private.json http://host.docker.internal:8080 fixtures/vc-c19-pcr-jwt-payload.json sample_vcs/lab_result.png
```

This sets the issuer to `http://host.docker.internal:8080`, which allows the sample verifier app to resolve port 8080 on the host during verification.


