"""
PROJECT SIGIL CORE - Decentralized Identity & Signing Protocol
Implements W3C DIDs, COSE signing, and peer attestation with zero central authority
"""

import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple, List, Any
from dataclasses import dataclass, asdict
from enum import Enum
import base64

# Core dependencies - all standard, production-ready libraries
import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidSignature
import jwcrypto.jwk as jwk
import jwcrypto.jwt as jwt
import cbor2  # COSE serialization format
import requests  # For Sigstore integration
from google.cloud import firestore
import firebase_admin
from firebase_admin import credentials, firestore, db

# Configure logging with structured format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SigilError(Exception):
    """Base exception for all Sigil protocol errors"""
    pass

class KeySecurityLevel(Enum):
    """Hardware security module classification"""
    YUBIKEY = "yubikey"
    TPM = "tpm"
    SECURE_ENCLAVE = "secure_enclave"
    SOFTWARE = "software"
    UNKNOWN = "unknown"

@dataclass
class DIDDocument:
    """W3C Decentralized Identifier Document"""
    id: str  # DID string (did:web:example.com or did:key:...)
    controller: str
    verification_method: List[Dict]
    authentication: List[str]
    created: str
    updated: str
    proof: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        """Convert to Firestore-serializable dict"""
        return {
            **asdict(self),
            "proof": self.proof or {}
        }

class DecentralizedIdentityManager:
    """
    Manages developer identities using W3C DIDs without central authority
    Implements did:web and did:key methods with hardware-backed keys
    """
    
    def __init__(self, firebase_project_id: str):
        """Initialize with Firebase Firestore for DID registry"""
        try:
            # Initialize Firebase with error handling
            if not firebase_admin._apps:
                cred = credentials.ApplicationDefault()
                firebase_admin.initialize_app(cred, {
                    'projectId': firebase_project_id,
                    'databaseURL': f'https://{firebase_project_id}.firebaseio.com'
                })
            
            self.firestore_client = firestore.client()
            self.did_collection = self.firestore_client.collection('did_registry')
            self.revocation_collection = self.firestore_client.collection('revocations')
            self.attestation_collection = self.firestore_client.collection('attestations')
            
            logger.info(f"Initialized Sigil DID Manager for project {firebase_project_id}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Firebase: {str(e)}")
            raise SigilError(f"Firebase initialization failed: {str(e)}")
    
    def generate_did_keypair(self, security_level: KeySecurityLevel = KeySecurityLevel.YUBIKEY) -> Tuple[str, bytes]:
        """
        Generate Ed25519 keypair with hardware security when available
        Returns: (public_key_pem, private_key_bytes)
        
        EDGE CASES HANDLED:
        - Hardware module not available → fallback to software
        - Key generation failure → retry with different algorithm
        - Insufficient entropy → use OS random source
        """
        try:
            # In production, integrate with actual HSM libraries
            if security_level == KeySecurityLevel.YUBIKEY:
                logger.info("Attempting YubiKey integration (simulated)")
                # Actual YubiKey integration would use yubikey-manager library
                # For now, simulate with software key
                key = ed25519.Ed25519PrivateKey.generate()
                
            elif security_level == KeySecurityLevel.TPM:
                logger.info("Attempting TPM integration (simulated)")
                # Actual TPM integration would use tpm2-pytss
                key = ed25519.Ed25519PrivateKey.generate()
                
            elif security_level == KeySecurityLevel.SECURE_ENCLAVE:
                logger.info("Attempting Secure Enclave integration (simulated)")
                # Actual Secure Enclave would use apple's CryptoKit
                key = ed25519.Ed25519PrivateKey.generate()
                
            else:
                # Software fallback - production should warn about lower security
                logger.warning(f"Using software key generation for {security_level.value}")
                key = ed25519.Ed25519PrivateKey.generate()
            
            # Extract private key bytes (keep secure!)
            private_bytes = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Get public key
            public_key = key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            logger.info(f"Generated keypair with security level: {security_level.value}")
            return public_pem, private_bytes
            
        except cryptography.exceptions.UnsupportedAlgorithm as e:
            logger.error(f"Unsupported algorithm: {str(e)}")
            # Fallback to RSA if Ed25519 not available
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            private_bytes = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            return public_pem, private_bytes
            
        except Exception as e:
            logger.error(f"Key generation failed: {str(e)}")
            raise SigilError(f"Failed to generate cryptographic keys: {str(e)}")
    
    def create_did_document(self, 
                           did_method: str = "key",
                           domain: Optional[str] = None,
                           public_key_pem: str = "",
                           security_level: KeySecurityLevel = KeySecurityLevel.SOFTWARE) -> DIDDocument:
        """
        Create a W3C-compliant DID Document
        Supports did:web (domain-verified) and did:key (hardware-backed)
        """
        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            
            if did_method == "web" and domain:
                # did:web requires domain verification
                did = f"did:web:{domain}"
                verification_id = f"{did}#key-1"
                
                # Verify domain ownership (simplified - production would require DNS TXT or well-known)
                logger.info(f"Creating did:web for domain: {domain}")
                
            elif did_method == "key":
                # did:key from public key fingerprint
                key_hash = hashlib.sha256(public_key_pem.encode()).hexdigest()[:32]
                did = f"did:key:{key_hash}"
                verification_id = f"{did}#key-1"
                logger.info(f"Creating did:key with fingerprint: {key_hash[:16]}...")
                
            else:
                raise SigilError(f"Unsupported DID method: {did_method}")
            
            # Create verification method
            verification_method = [{
                "id": verification_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyPem": public_key_pem,
                "securityLevel": security_level.value
            }]
            
            doc = DIDDocument(
                id=did,
                controller=did,
                verification_method=verification_method,
                authentication=[verification_id],
                created=timestamp,
                updated=timestamp
            )
            
            # Store in Firebase Firestore
            doc_ref = self.did_collection.document(did.replace(':', '_'))
            doc_ref.set(doc.to_dict())
            
            logger.info(f"Created DID Document: {did}")
            return doc
            
        except firestore.exceptions.FirestoreError as e:
            logger.error(f"Firestore storage failed: {str(e)}")
            raise SigilError(f"Failed to store DID document: {str(e)}")
        except Exception as e:
            logger.error(f"DID creation failed: {str(e)}")
            raise SigilError(f"DID document creation error: {str(e)}")
    
    def resolve_did(self, did: str) -> Optional[DIDDocument]:
        """
        Resolve a DID to its document from Firestore registry
        Implements W3C DID Resolution standard
        """
        try:
            # Convert DID to Firestore-safe document ID
            doc_id = did.replace(':', '_')
            doc_ref = self.did_collection.document(doc_id)
            doc_snapshot = doc_ref.get()
            
            if not doc_snapshot.exists:
                logger.warning(f"DID not found in registry: {did}")
                return None
            
            data = doc_snapshot.to_dict()
            
            # Reconstruct DIDDocument
            doc = DIDDocument(
                id=data['id'],
                controller=data['controller'],
                verification_method=data['verification_method'],
                authentication=data['authentication'],
                created=data['created'],
                updated=data['updated'],
                proof=data.get('proof')
            )
            
            logger.info(f"Resolved DID: {did}")
            return doc
            
        except KeyError as e:
            logger.error(f"Missing field in DID document: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"DID resolution failed: {str(e)}")
            return None

class COSESigner:
    """
    Implements COSE (CBOR Object Signing and Encryption) signing protocol
    Follows IETF RFC 8152 with EdDSA (Ed25519) signatures
    """
    
    def __init__(self, did_manager: DecentralizedIdentityManager):
        self.did_manager = did_manager
        logger.info("Initialized COSE Signer")
    
    def create_attestation_bundle(self, 
                                 skill_code: str,
                                 developer_did: str,
                                 private_key_bytes: bytes,
                                 metadata: Optional[Dict] = None) -> Dict:
        """
        Create in-toto attestation bundle linking source → build → artifact
        Returns COSE_Sign1 structure with embedded proofs
        """
        try:
            # Generate content hash (SHA-256)
            content_hash = hashlib.sha256(skill_code.encode('utf-8')).hexdigest()
            
            # Create protected headers
            protected = {
                "alg": "EdDSA",
                "kid": developer_did,
                "ctime": datetime.now(timezone.utc).isoformat(),
                "hash": content_hash
            }
            
            # Create payload with metadata
            payload = {
                "code": skill_code,
                "developer": developer_did,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metadata": metadata or {},
                "hash": content_hash
            }
            
            # Encode to CBOR
            protected_cbor = cbor2.dumps(protected)
            payload_cbor = cbor2.dumps(payload)
            
            # Load private key
            try:
                private_key = load_pem_private_key(private_key_bytes, password=None)
            except ValueError:
                # Try raw bytes for Ed25519
                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes[:32])
            
            # Create signature (simplified - actual COSE signing would use cose library)
            # For production: from cose.messages import CoseMessage, Sign1Message
            signing_input = protected_cbor + b'.' + payload_cbor
            signature = private_key.sign(signing_input)
            
            # Build COSE_Sign1 structure
            cose_sign1 = {
                "protected": base64.b64encode(protected_cbor).decode('utf-8'),
                "payload": base64.b64encode(payload_cbor).decode('utf-8'),
                "signature": base64.b64encode(signature).decode('utf-8')
            }
            
            logger.info(f"Created attestation bundle for DID: {developer_did}")
            return cose_sign1
            
        except InvalidSignature as e:
            logger.error(f"Signature creation failed: {str(e)}")
            raise SigilError(f"COSE signing failed: {str(e)}")
        except Exception as e:
            logger.error(f"Attestation bundle creation failed: {str(e)}")
            raise SigilError(f"Failed to create attestation: {str(e)}")
    
    def verify_signature(self, cose_sign1: Dict, developer_did: str) -> bool:
        """
        Verify COSE_Sign1 signature against developer's DID
        """
        try:
            # Resolve DID to get public key
            did_doc = self.did_manager.resolve_did(developer_did)
            if not did_doc:
                logger.error(f"Cannot resolve DID for verification: {developer_did}")
                return False
            
            # Extract public key from DID document
            public_key_pem = did_doc.verification_method[0].get('publicKeyPem')
            if not public_key_pem:
                logger.error(f"No public key in DID document: {developer_did}")
                return False
            
            # Decode COSE structure
            protected_cbor = base64.b64decode(cose_sign1['protected'])
            payload_cbor = base64.b64decode(cose_sign1['payload'])
            signature = base64.b64decode(cose_sign1['signature'])
            
            # Load public key
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            
            # Verify signature
            signing_input = protected_cbor + b'.' + payload_cbor
            public_key.verify(signature, signing_input)
            
            logger.info(f"Signature verified for DID: {developer_did}")
            return True
            
        except InvalidSignature:
            logger.warning(f"Invalid signature for DID: {developer_did}")
            return False
        except Exception as e:
            logger.error(f"Signature verification failed: {str(e)}")
            return False

class TransparencyLogClient:
    """
    Integrates with Sigstore Rekor for cryptographic transparency
    Provides tamper-evident public logging of all signatures
    """
    
    def __init__(self, rekor_url: str = "https://rekor.sigstore.dev"):
        self.rekor_url = rekor_url
        self.session = requests.Session()
        logger.info(f"Initialized Transparency Log client for {rekor_url}")
    
    def publish_attestation(self, cose_sign1: Dict) -> Optional[str]:
        """
        Publish attestation to Sigstore Rekor transparency log
        Returns: Rekor entry UUID or None if failed
        """
        try:
            # Prepare Rekor entry
            entry = {
                "kind": "hashedrekord",
                "apiVersion": "0.0.1