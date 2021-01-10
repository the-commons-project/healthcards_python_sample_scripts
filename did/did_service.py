import canonicaljson
import json
import hashlib
import multihash
from jwcrypto.common import base64url_encode, base64url_decode

from .did import DID, DIDPublicKey, DIDPatch, DIDUpdate, DIDSuffix, DIDPublicKeyDocumentEntry, DIDPublicKeyDocument, DIDLongFormSuffix

class DIDService:

    def _sha256Digest(self, data):
        m = hashlib.sha256()
        m.update(data)
        return m.digest()

    def _hashData(self, data):
        digest = self._sha256Digest(data)
        return multihash.encode(self._sha256Digest(data), 18)

    def _base64URLEncode(self, data):
        return base64url_encode(data)

    def _base64URLDecode(self, data):
        return base64url_decode(data)

    def _canonicalize(self, d):
        return canonicaljson.encode_canonical_json(d)

    def _revealCommitPair(self, signingPublicKeyDict):
        revealValueBytes = self._canonicalize(signingPublicKeyDict)
        commitmentHash = self._hashData(revealValueBytes)
        commitmentHashEncodedString = self._base64URLEncode(commitmentHash)
        return (revealValueBytes.decode('utf-8'), commitmentHashEncodedString)


    ## JDK - keys must be dict objects
    def create_did(
        self,
        signingKeyName,
        signingKey,
        ecEncryptionKeyName,
        ecEncryptionKey,
        updateKey,
        recoveryKey
    ):
        recovery_commitment = self._revealCommitPair(recoveryKey)[1]
        update_commitment = self._revealCommitPair(updateKey)[1]

        otherPublicKeys = [
            DIDPublicKey(
                signingKeyName,
                ['general', 'auth'],
                "JsonWebKey2020",
                signingKey
            ),
            DIDPublicKey(
                ecEncryptionKeyName,
                ['general', 'auth'],
                "JsonWebKey2020",
                ecEncryptionKey
            )
        ] 

        patches = [
            DIDPatch(
                "add-public-keys",
                otherPublicKeys
            )
        ]


        delta = DIDUpdate(
            update_commitment,
            patches
        )

        deltaCanonical = self._canonicalize(delta.as_dict())
        deltaEncoded = self._base64URLEncode(deltaCanonical)

        deltaHash = self._base64URLEncode(
            self._hashData(deltaCanonical)
        )

        suffixData = DIDSuffix(
            deltaHash,
            recovery_commitment
        )

        suffixDataCanonical = self._canonicalize(suffixData.as_dict())
        suffixHash = self._hashData(suffixDataCanonical)
        suffix = self._base64URLEncode(
            self._hashData(suffixDataCanonical)
        )

        suffixDataEncoded = self._base64URLEncode(suffixDataCanonical)

        long_form_suffix = DIDLongFormSuffix(
            delta,
            suffixData
        )

        long_form_suffix_canonical = self._canonicalize(long_form_suffix.as_dict())
        long_form_suffix_encoded = self._base64URLEncode(long_form_suffix_canonical)

        didShort = f'did:ion:{suffix}'
        initialState = f'{suffixDataEncoded}.{deltaEncoded}'
        didLong = f'did:ion:{suffix}:{long_form_suffix_encoded}'

        return DID(
            didShort,
            initialState,
            didLong
        )

    def _get_keys_from_update(self, update):
        keys = []
        for patch in update.patches:
            if patch.action == 'add-public-keys':
                for key in patch.public_keys:
                    entry = DIDPublicKeyDocumentEntry(
                        f'#{key.id}',
                        None,
                        None,
                        key.type,
                        key.jwk
                    )
                    keys.append(entry)
        return keys


    def resolve_did(self, did):
        suffixAndDelta = did.split("?-ion-initial-state=")[1]
        deltaEncoded = suffixAndDelta.split(".")[1]
        deltaJSON = self._base64URLDecode(deltaEncoded)
        delta = DIDUpdate.from_dict(json.loads(deltaJSON))

        keys = self._get_keys_from_update(delta)
        return DIDPublicKeyDocument(
            keys
        )

    def resolve_key(self, key_id):
        split = key_id.split("#")
        did = split[0]
        kid = split[1]

        did_document = self.resolve_did(did)
        for key_entry in did_document.public_keys:
            if key_entry.id == f'#{kid}':
                return key_entry.public_key_dict

