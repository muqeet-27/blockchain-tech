import hashlib
import base58
import json
import time
import re
from typing import Dict, List, Optional, Union
import logging
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DIDError(Exception):
    """Custom exception for DID-related errors"""
    pass

class DIDMethod(Enum):
    """Supported DID methods"""
    PEER = "peer"
    WEB = "web"
    KEY = "key"

@dataclass
class DIDDocument:
    """DID Document structure"""
    id: str
    created: str
    updated: Optional[str] = None
    public_keys: List[Dict] = None
    authentication: List[str] = None
    service_endpoints: List[Dict] = None

    def __post_init__(self):
        if self.public_keys is None:
            self.public_keys = []
        if self.authentication is None:
            self.authentication = []
        if self.service_endpoints is None:
            self.service_endpoints = []

class DIDManager:
    """Enhanced DID management with validation and additional features"""

    # Regex pattern for validating DID format
    DID_PATTERN = re.compile(r'^did:([a-z0-9]+):([a-zA-Z0-9._-]+)$')

    @staticmethod
    def validate_public_key(pub_key_hex: str) -> bool:
        """
        Validate public key format

        Args:
            pub_key_hex (str): Public key in hexadecimal format

        Returns:
            bool: True if valid format

        Raises:
            DIDError: If validation fails
        """
        if not pub_key_hex:
            raise DIDError("Public key cannot be empty")

        try:
            key_bytes = bytes.fromhex(pub_key_hex)
            # Basic length validation for ECDSA public keys (usually 64 bytes)
            if len(key_bytes) not in [33, 64, 65]:  # Compressed, uncompressed formats
                raise DIDError(f"Invalid key length: {len(key_bytes)} bytes")
            return True
        except ValueError:
            raise DIDError("Invalid hexadecimal format for public key")

    @staticmethod
    def create_peer_did(pub_key_hex: str, version: int = 2) -> str:
        """
        Create a Peer DID using Method 2 specification

        Args:
            pub_key_hex (str): Public key in hexadecimal format
            version (int): Peer DID version (default: 2)

        Returns:
            str: Complete DID string

        Raises:
            DIDError: If DID creation fails
        """
        if version != 2:
            raise DIDError(f"Unsupported Peer DID version: {version}")

        # Validate public key
        DIDManager.validate_public_key(pub_key_hex)

        try:
            # Create multicodec prefix for SHA-256 hash (0x12 = sha2-256, 0x20 = 32 bytes)
            multicodec_prefix = b'\x12\x20'

            # Hash the public key
            key_hash = hashlib.sha256(bytes.fromhex(pub_key_hex)).digest()

            # Combine prefix and hash
            multicodec_key = multicodec_prefix + key_hash

            # Encode using base58
            encoded_key = base58.b58encode(multicodec_key).decode('utf-8')

            # Create the DID
            did = f"did:peer:{version}.Vz{encoded_key}"

            logger.info(f"Peer DID created successfully: {did}")
            return did

        except Exception as e:
            logger.error(f"Peer DID creation failed: {e}")
            raise DIDError(f"Failed to create Peer DID: {e}")

    @staticmethod
    def validate_did(did: str) -> Dict[str, str]:
        
        if not did:
            raise DIDError("DID cannot be empty")

        match = DIDManager.DID_PATTERN.match(did)
        if not match:
            raise DIDError(f"Invalid DID format: {did}")

        method, identifier = match.groups()

        return {
            'method': method,
            'identifier': identifier,
            'full_did': did
        }

    @staticmethod
    def create_did_document(did: str, pub_key_hex: str, 
                          service_endpoints: Optional[List[Dict]] = None) -> DIDDocument:
        
        # Validate inputs
        DIDManager.validate_did(did)
        DIDManager.validate_public_key(pub_key_hex)

        current_time = time.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Create public key entry
        public_key = {
            'id': f"{did}#key-1",
            'type': 'EcdsaSecp256k1VerificationKey2019',
            'controller': did,
            'publicKeyHex': pub_key_hex
        }

        # Create DID document
        doc = DIDDocument(
            id=did,
            created=current_time,
            public_keys=[public_key],
            authentication=[f"{did}#key-1"],
            service_endpoints=service_endpoints or []
        )

        return doc

    @staticmethod
    def rotate_key(old_did: str, new_pub_key_hex: str) -> str:
         
        # Validate old DID
        DIDManager.validate_did(old_did)

        # Create new DID with new key
        new_did = DIDManager.create_peer_did(new_pub_key_hex)

        logger.info(f"Key rotation: {old_did} -> {new_did}")
        return new_did

    @staticmethod
    def resolve_did(did: str) -> Optional[Dict]:
        
        # In a real implementation, this would query a DID registry/network
        logger.info(f"Resolving DID: {did}")
        return None

    @staticmethod
    def create_web_did(domain: str, path: str = "") -> str:
        
        if not domain:
            raise DIDError("Domain cannot be empty")

        # Basic domain validation
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            raise DIDError(f"Invalid domain format: {domain}")

        if path:
            identifier = f"{domain}:{path.replace('/', ':')}"
        else:
            identifier = domain

        web_did = f"did:web:{identifier}"
        logger.info(f"Web DID created: {web_did}")
        return web_did

class DIDRegistry:
    """Simple in-memory DID registry for demonstration purposes"""

    def __init__(self):
        self.registry: Dict[str, DIDDocument] = {}
        logger.info("DID Registry initialized")

    def register(self, did_document: DIDDocument) -> bool:
        """Register a DID document"""
        try:
            self.registry[did_document.id] = did_document
            logger.info(f"DID registered: {did_document.id}")
            return True
        except Exception as e:
            logger.error(f"DID registration failed: {e}")
            return False

    def resolve(self, did: str) -> Optional[DIDDocument]:
        """Resolve a DID to get its document"""
        return self.registry.get(did)

    def update(self, did: str, updated_document: DIDDocument) -> bool:
        """Update an existing DID document"""
        if did not in self.registry:
            logger.warning(f"DID not found for update: {did}")
            return False

        updated_document.updated = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.registry[did] = updated_document
        logger.info(f"DID updated: {did}")
        return True

    def deactivate(self, did: str) -> bool:
        """Deactivate a DID (remove from registry)"""
        if did in self.registry:
            del self.registry[did]
            logger.info(f"DID deactivated: {did}")
            return True
        return False

    def list_dids(self) -> List[str]:
        """List all registered DIDs"""
        return list(self.registry.keys())

# Legacy function names for backward compatibility
def create_peer_did(pub_key_hex: str) -> str:
    """Legacy function for backward compatibility"""
    return DIDManager.create_peer_did(pub_key_hex)

def update_did(old_did: str, new_pub_key_hex: str) -> str:
    """Legacy function for backward compatibility"""
    return DIDManager.rotate_key(old_did, new_pub_key_hex)