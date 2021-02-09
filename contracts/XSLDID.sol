// SPDX-License-Identifier: UNLICENSED
// (c) Copyright 2021 xsl, all rights reserved.
pragma solidity ^0.7.4;
pragma experimental ABIEncoderV2;

/**
    @title XSL Labs contract
    @author XSL Labs Team
    @notice DID and Verifable Credential Registery
 */

contract XSLDID {

    // Admin Address (XSL Labs)
    address public  admin;

    // Mini DID Document
    struct DIDDocument {
        bytes authenticationKey;
        address Controller;
        bytes32 Service;
    }

    mapping (address => DIDDocument ) DIDs;
    mapping(address => bool) public isIssuer;
    mapping(address => uint) public changed;
    mapping(address => uint) public nonce;
    mapping (bytes32 =>   mapping(address => uint)) VCs;

    /*
     *  Modifiers
     */
    modifier onlyAdmin() {
        require(msg.sender == admin);
        _;
    }
    modifier onlyAuthorized() {
        require(msg.sender == admin || isIssuer[msg.sender]);
        _;
    }
    modifier issuerDoesNotExist(address _issuer) {
        require(!isIssuer[_issuer], "This issuer already exists");
        _;
    }
    modifier issuerExists(address _issuer) {
        require(isIssuer[_issuer], "This issuer does not exist");
        _;
    }
    modifier identityNotExist(address _identity) {
        require(DIDs[_identity].authenticationKey.length == 0, "This identity aleady exists");
        _;
    }
    modifier identityExists(address _identity) {
        require(DIDs[_identity].authenticationKey.length > 0, "This identity does not exist");
        _;
    }
    modifier notNull(address _address) {
        require(_address != address(0), "This value must not be empty");
        _;
    }
    modifier onlyOwner(address _identity, address _controller) {
        require (_controller == DIDs[_identity].Controller);
        _;
    }

    /*
     *  Events
     */
    event DIDAttributeChanged(
        address indexed identity,
        bytes32 name,
        string value,
        uint validTo,
        uint previousChange
    );

    /**
        @dev 						smart contract initialization (sets the deployer as the initial owner)
        @param _authenticationKey   Admin authentication key
        @param _service             Admin public profile (IPFS Profile)
    */
    constructor (bytes memory _authenticationKey, bytes32  _service){
        admin = msg.sender;
        DIDs[msg.sender] =  DIDDocument(_authenticationKey,msg.sender,_service);
    }

    /**
      @dev Creates a mini DID Document for "_identity" address with
        - authentication key,
        - controller,
        - verifiable credential signature key
        - verifiable credential service url
        reserved for Admin
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
                   "id": "did:syl:0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db#CV",
                   "type": "Verifiable Credential",
                   "serviceEndpoint": "www.xsl-labs.io"
                 }
               ]
            }
      @param _identity              User Address (used as Identifier)
      @param _authenticationKey    	Authentication Key (hex format)
      @param _service               Verifable Credential url
    */
    function creatDID (address _identity, bytes memory _authenticationKey, bytes32  _service) external
        onlyAuthorized()
        notNull(_identity)
        identityNotExist(_identity) {

            DIDs[_identity] = DIDDocument(_authenticationKey,_identity,_service);
    }

    /**
      @dev Creates a mini DID Document for "_identity" address with
        - authentication key,
        - controller,
        - verifiable credential signature key
        - public profile service IPFS url
        reserved for Admin
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
      @param _identity             	User Address (used as Identifier )
      @param _authenticationKey    	Authentication Key (hex format)
      @param _service				Public profile IPFS url
    */
    function creatDIDForIssuer (address _identity, bytes memory _authenticationKey, bytes32 _service) external
        onlyAdmin()
        notNull(_identity)
        issuerDoesNotExist(_identity) {

            DIDs[_identity] =  DIDDocument(_authenticationKey,_identity,_service);
            isIssuer[_identity] = true;
    }

    /**
      @dev Store 				Verifiable credential trace (Hash) associated to issuer address and time
      @param _hashVC			Verifiable credentialhash (SHA256)
      @param _issuerIdentity	Issuer Address
     */
    function addVC ( bytes32 _hashVC, address _issuerIdentity) external
        onlyAdmin()
        issuerExists(_issuerIdentity) {

            VCs[_hashVC][_issuerIdentity] = block.timestamp;
    }
    /**
      @dev 						Controller identity change (only used internally by Smart Contract).
      @param _identity          Identity address
      @param _controller        Current controller address
      @param _newController     New controller address
     */
    function changeController(address _identity, address _controller,  address _newController) internal
        onlyOwner(_identity, _controller) {

             DIDs[_identity].Controller = _newController;
    }

    /**
      @dev 						Controller identity change
      @param _identity       	Identity address
      @param _controller        New controller address
     */
    function changeController(address _identity,  address _controller) public
        identityExists(_identity)
        notNull(_controller) {

            changeController(_identity, msg.sender, _controller);
    }

    /**
      @dev 					Controller identity change through off-chain signature by current controller private key
      @param sigV           Recovery identifier
      @param sigR           Signature value R  (message to be signed == 0x19 + 0x00 + Smart Contract Address + Nonce + Identity Address
      @param sigS           Signature value S   + "changeController" + new controller address)
      @param _controller    New controller address
     */
    function changeControllerSigned(address _identity, uint8 sigV, bytes32 sigR, bytes32 sigS, address _controller) public
        identityExists(_identity)
        notNull(_controller) {

            bytes32 hash = keccak256(abi.encodePacked(byte(0x19), byte(0), this, nonce[DIDs[_identity].Controller], _identity, "changeController", _controller));
            changeController(_identity, checkSignature(_identity, sigV, sigR, sigS, hash), _controller);
    }


    /**
      @dev 					Event emission to add attribute to identity address (DIDAttributeChanged)
      @param _identity      Identity address
      @param _controller    Current controller address
      @param name           Attribute name
                                example: Auth/Secp256k1/VeriKey/publicKeyHex (add Authentication Key with Type EcdsaSecp256k1VerificationKey2019 with hex encoded public key)
      @param value          Attribute value
                                ewample: 0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71
      @param validity		Validity period
     */
    function setAttribute(address _identity, address _controller, bytes32 name, string memory value, uint validity ) internal
        onlyOwner(_identity, _controller) {

            emit DIDAttributeChanged(_identity, name, value, block.timestamp + validity, changed[_identity]);
            changed[_identity] = block.number;
    }

    function setAttribute(address _identity, bytes32 name, string memory value, uint validity) public
        identityExists(_identity) {

            setAttribute(_identity, msg.sender, name, value, validity);
    }
    /**
      @dev 					Event emission to add attribute to identity address through off-chain signature with current controller private key
      @param _identity      Identity address
      @param sigV           Recovery identifier
      @param sigR           Signature value R  (message to be signed == 0x19 + 0x00 + Smart Contract Address + Nonce + Identity Address
      @param sigS           Signature value S   + "setAttribute" + name + value + validity)
      @param name           Attribute name
                                example: Auth/Secp256k1/VeriKey/publicKeyHex (add Authentication Key with Type EcdsaSecp256k1VerificationKey2019 with hex encoded public key)
      @param value          Attribute value
                                ewample: 0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71
      @param validity		Validity period
     */
    function setAttributeSigned(address _identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, string memory value, uint validity) public
        identityExists(_identity) {

            bytes32 hash = keccak256(abi.encodePacked(byte(0x19), byte(0), this, nonce[_identity], _identity, "setAttribute", name, value, validity));
            setAttribute(_identity, checkSignature(_identity, sigV, sigR, sigS, hash), name, value, validity);
    }
    /**
      @dev 					Even emission to revoke attribute to identity address (DIDAttributeChanged).
      @param _identity      Identity address
      @param _controller    Current controller address
      @param name           Attribute name
                                example: Auth/Secp256k1/VeriKey/publicKeyHex (add Authentication Key with Type EcdsaSecp256k1VerificationKey2019 with hex encoded public key)
      @param value          Attribute value
                                example: 0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71
     */
    function revokeAttribute(address _identity, address _controller, bytes32 name, string memory value) internal
        onlyOwner(_identity, _controller) {

            emit DIDAttributeChanged(_identity, name, value, 0, changed[_identity]);
            changed[_identity] = block.number;
    }

    function revokeAttribute(address _identity, bytes32 name, string memory value) public
        identityExists(_identity) {

            revokeAttribute(_identity, msg.sender, name, value);
    }

    function revokeAttributeSigned(address _identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, string memory value, uint validity) public
        identityExists(_identity) {

            bytes32 hash = keccak256(abi.encodePacked(byte(0x19), byte(0), this, nonce[_identity], _identity, "setAttribute", name, value, validity));
            revokeAttribute(_identity, checkSignature(_identity, sigV, sigR, sigS, hash), name, value);
    }

    /**
      @dev 					Signature validity check
      @param _identity   	Signer address
      @param sigV           Recovery identifier
      @param sigR           Signature value R
      @param sigS           Signature value S
      @param hash           Hash of signed value
     */
   function checkSignature(address _identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 hash) internal returns(address) {
            address signer = ecrecover(hash, sigV, sigR, sigS);
            require(signer == DIDs[_identity].Controller);
            nonce[_identity]++;
            return signer;
   }

    /**
      @dev 					Mini DID retrieval (associated to identity address)
      @param _identity      Identity address
    */
    function getDID(address _identity) public view returns(DIDDocument memory){
        return DIDs[_identity];
    }
    /**
      @dev 					Verifiable Credential trace timestamp retrieval (from verifiable credential hash and issuer address)
      @param _hashVC        Verifiable credential hash
      @param _issuerAddress	Issuer Address
     */
    function getVCtimestamp(bytes32 _hashVC, address _issuerAddress) public view returns(uint){
       return VCs[_hashVC][_issuerAddress];
    }

}
