
class DID:
    def __init__(self, shortIdentifier, longIdentifier):
        self.shortIdentifier = shortIdentifier
        self.longIdentifier = longIdentifier

class DIDPublicKey:
    def __init__(self, key_id, purpose, key_type, jwk):
        self.id = key_id
        self.purpose = purpose
        self.type = key_type
        self.jwk = jwk

    def as_dict(self):
        return {
            'id': self.id,
            'purpose': self.purpose,
            'type': self.type,
            'jwk': self.jwk
        }

    @staticmethod
    def from_dict(d):
        return DIDPublicKey(
            d['id'],
            d['purpose'],
            d['type'],
            d['jwk']
        )

class DIDPatch:
    def __init__(self, action, public_keys):
        self.action = action
        self.public_keys = public_keys

    def as_dict(self):
        public_keys = [key.as_dict() for key in self.public_keys]
        return {
            'action': self.action,
            'public_keys': public_keys
        }

    @staticmethod
    def from_dict(d):
        public_keys = [DIDPublicKey.from_dict(key) for key in d.get('public_keys', [])]
        return DIDPatch(
            d['action'],
            public_keys
        )

class DIDUpdate:
    def __init__(self, update_commitment, patches):
        self.update_commitment = update_commitment
        self.patches = patches

    def as_dict(self):
        patches = [patch.as_dict() for patch in self.patches]
        return {
            'update_commitment': self.update_commitment,
            'patches': patches
        }

    @staticmethod
    def from_dict(d):
        patches = [DIDPatch.from_dict(patch) for patch in d['patches']]
        return DIDUpdate(
            d['update_commitment'],
            patches
        )

class DIDSuffix:
    def __init__(self, delta_hash, recovery_commitment):
        self.delta_hash = delta_hash
        self.recovery_commitment = recovery_commitment

    def as_dict(self):
        return {
            'delta_hash': self.delta_hash,
            'recovery_commitment': self.recovery_commitment
        }

class DIDPublicKeyDocumentEntry:
    def __init__(self, key_id, usage, controller, key_type, public_key_dict):
        self.id = key_id
        self.usage = usage
        self.controller = controller
        self.type = key_type
        self.public_key_dict = public_key_dict

    def as_dict(self):

        d = {
            'id': self.id,
            'type': self.type,
            'publicKeyJwk': self.public_key_dict
        }

        if self.usage:
            d['usage'] = self.usage
        if self.controller:
            d['controller'] = self.controller

        return d

    @staticmethod
    def from_dict(d):
        return DIDPublicKeyDocumentEntry(
            d.get('id'),
            d.get('usage'),
            d.get('controller'),
            d.get('type'),
            d.get('publicKeyJwk')
        )
    

class DIDPublicKeyDocument:
    def __init__(self, public_keys):
        self.public_keys = public_keys

    def as_dict(self):
        public_keys = [key.as_dict() for key in self.public_keys]
        return {
            'publicKey': public_keys
        }

    @staticmethod
    def from_dict(d):
        keys = [DIDPublicKeyDocumentEntry.from_dict(key) for key in d['publicKey']]
        return DIDPublicKeyDocument(
            keys
        )

