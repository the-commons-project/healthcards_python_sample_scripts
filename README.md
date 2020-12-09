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

## Generate a DID
To generate a random DID, use the following command:

```
python generate_random_did.py did.json
```

This script will generate the necessary JWK formatted keys and create a new DID based on them, saving them `did.json`.

## Generate a VC
To generate a sample VC, use the following command:

```
python encode_resource.py did.json ./fixtures/vc-c19-pcr-jwt-payload.json sample_vcs/sample.fhir-backed-vc
```

This script uses the DID config defined in `did.json`, generates a new VC based on `./fixtures/vc-c19-pcr-jwt-payload.json`, and saves that in `sample_vcs/sample.fhir-backed-vc`.

## Verify a VC
To verifiy a VC, use the following command:

```
python decode_resource.py sample_vcs/sample.fhir-backed-vc
```

This script loads the VC from `sample_vcs/sample.fhir-backed-vc`, and verifies it based on the DID encoded in the JWS header.


