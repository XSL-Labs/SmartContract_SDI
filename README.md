---
title: "SDI Ethereum Smart Contract"
index: 0
category: "DID Smart Contrat"
type: "reference"
source: "https://github.com/XSL-Labs/SmartContract_SDI/blob/main/README.md"
---

#  SDI Smart Contract 

DID Identifier allows you to lookup an associated DID document that contains public keys and attributes.

This referenced keys can be used to authenticate you, to verify your signature, ton encrypt mesage for you.

### function creatDID 

@dev Creates a mini DID Document for "_identity" address with
- authentication key,
- controller,
- verifiable credential signature key
- public profile service IPFS url
reserved for Admin


### function creatDIDForIssuer

@dev Creates a mini DID Document for "_identity" address with
- authentication key,
- controller,
- verifiable credential signature key
- public profile service IPFS url

Example:
{
   "context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/v1"],
   "id": "did:syl:0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db",
   "controller": "did:syl:0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db",
   "authentication": [
	 {
	   "did:syl:0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db#keyAuth-1",
	   "type": "EcdsaSecp256r1Signature2019",
	   "controller": "did:syl:0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db",
	   "publicKeyBase58": "027560af3387d375e3342a6968179ef3c6d04f5d33b2b611cf326d4708badd7770"
	 }
   ],
   "assertionMethod": [
	 {
	 "did:syl:0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db#VC-Signature",
	 "type": "EcdsaSecp256k1Signature2019",
	 "controller": "did:syl:0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db",
	 "ethereumAddress": "0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db"
	 }
   ],
   "service": [
	 {
	   "id": "did:syl:0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db#Public_Profile",
	   "type": "Public Profile",
	   "serviceEndpoint": "https://ipfs.infura.io/ipfs/QmNTMEmwUTG5mFhdRrsiAADPed1i4HccbhCcbdALAyyxLE"
	 }
   ]
}






