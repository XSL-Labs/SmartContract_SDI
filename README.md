---
title: "SDI Ethereum Smart Contract"
index: 0
category: "DID Smart Contrat"
type: "reference"
source: "https://github.com/XSL-Labs/SmartContract_SDI/README.md"
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
```javascript
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
```

## Off-chain transaction
Since each Ethereum transaction must be funded, there is a growing trend of on-chain transactions that are authenticated via an externally created signature and not by the actual transaction originator. This allows for 3rd party funding services, or for receivers to pay without any fundamental changes to the underlying Ethereum architecture.

These kinds of transactions have to be signed by an actual key pair and thus cannot be used to represent smart contract based Ethereum accounts.


## Identifier
Any Ethereum address can be used as identifier.
Avery identity should demande registration to XSL labs (Admin) with a KYC process.
Identity DID document created as well as their first verifiable identifier.

## Identity Ownership
Each identity has a single address which maintains ultimate control over it. By default, each identity is controlled by itself. As ongoing technological and security improvements occur, an owner can replace themselves with any other Ethereum address, such as an advanced multi-signature contract.

### Looking up Identity Ownership
Ownership of identity is the controller of the DID document.
Calling the  getDID(address _identity) public view returns(DIDDocument memory)  where DIDDocument is a structure 
struct DIDDocument { bytes authenticationKey; address Controller; bytes32 Service;}
This returns a mini DIDdcouement where the Controller Address is the current identity Owner.

### Changing Identity Ownership
The account owner can replace themselves at any time, by calling the change changeController(address _identity,  address _controller)  function

There is also a version of this function which is called with an externally created signature, that is passed to a transaction funding service.

The externally signed version has the following signature changeControllerSigned(address _identity, uint8 sigV, bytes32 sigR, bytes32 sigS, address _controller).

The signature should be signed of the keccak256 hash of the following tightly packed parameters:

byte(0x19), byte(0), address of smart contract, nonce[currentController], _identity, "changeController", _controller


## Adding Attributes
An identity may need to publish some information that is only needed off-chain but still requires the security benefits of using a blockchain.

These attributes are set using the  setAttribute(address _identity, bytes32 name, string memory value, uint validity) function and published using events.

There is also a version of this function that is called with an externally created signature, that is passed to a transaction funding service.

The externally signed version has the following signature setAttributeSigned(address _identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, string memory value, uint validity).

The signature should be signed off the keccak256 hash of the following tightly packed parameters:

byte(0x19), byte(0), address of smart contract, nonce[currentController], _identity, "setAttribute", name, value, validity
 
### Revoking Attributes
These attributes are revoked using the revokeAttribute(address _identity, bytes32 name, string memory value) function and published using events.

There is also a version of this function that is called with an externally created signature, that is passed to a transaction funding service.

The externally signed version has the following signature revokeAttributeSigned(address _identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, string memory value).

The signature should be signed off the keccak256 hash of the following tightly packed parameters:

byte(0x19), byte(0), address of smart contract, nonce[currentController], _identity, "revokeAttribute", name, value

### Reading attributes
Attributes are stored as DIDAttributeChanged events. A validTo of 0 indicates a revoked attribute.


 event DIDAttributeChanged(
        address indexed identity,
        bytes32 name,
        string value,
        uint validTo,
        uint previousChange
    );

Where name is a representation of string shorter than 32 bytes right-padded if need to get the 32 bytes 
Example : Auth/Secp256k1/VeriKey/Hex —> 000000000000417574682f536563703235366b312f566572694b65792f486578
( means add Authentication Key with Type EcdsaSecp256k1VerificationKey2019 with hex encoded public key)


## Enumerating Linked Identity Events
Contract Events are a useful feature for storing data from smart contracts exclusively for off-chain use. Unfortunately, current Ethereum implementations provide a very inefficient lookup mechanism.

Each identity has its previously changed block stored in the changed mapping.
1 - Lookup previousChange block for identity
2 - Lookup all events for a given identity address using web3, but only for the previousChange   
     block
3 - Do something with the event
4 - Find previousChange from the event and repeat


## Assemble a DID Document
First you start getting the mini DID document from smart contract of an identity  using 
getDID(address _identity) public view returns(DIDDocument memory). 

Second iterate through DIDAttributeChanged  events for services and/or  verification methods 

Example:
```javascript
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
```

### Verifiable Credential 

Only admin can set a prof of a verifiable credential from Issuer ( KYC)
Storing hash of private verifiable credential with the time of creation.
Storing an IPFS ref of public verifiable credential associated to the identity address and time.




