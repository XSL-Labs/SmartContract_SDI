// SPDX-License-Identifier: XSL
// (c) Copyright 2021 xsl, all rights reserved.
pragma solidity ^0.7.4;

/**
    @title XSL Labs contract
    @author XSL Labs Team
    @notice DID and Verifable Credential Registery
 */
import "./IERC173.sol";
contract XSLDID is IERC173 {

    // Admin Address (XSL Labs)
    address public  admin;

    // Mini DID Document
    struct DIDDocument {
        address Controller;
        bytes32 Service;
        bytes AuthenticationKey;
    }
    struct PublicVC {
        bytes32 IpfsRef;
        uint time;
    }
    mapping (address => DIDDocument ) DIDs;
    mapping(address => bool) public isIssuer;
    mapping(address => uint) public changed;
    mapping(address => uint) public nonce;
    mapping (bytes32 =>   mapping(address => uint)) VCs;
    mapping (address =>   PublicVC[]) VCsPublic;
    /*
     *  Modifiers
     */
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can do that");
        _;
    }
    modifier onlyAuthorized() {
        require(isIssuer[msg.sender], "Only Admin and Issuer can do that");
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
        require(DIDs[_identity].AuthenticationKey.length == 0, "This identity aleady exists");
        _;
    }
    modifier identityExists(address _identity) {
        require(DIDs[_identity].AuthenticationKey.length > 0, "This identity does not exist");
        _;
    }
    modifier notNull(address _address) {
        require(_address != address(0), "This value must not be empty");
        _;
    }
    modifier onlyOwner(address _identity, address _controller) {
        require (_controller == DIDs[_identity].Controller, "Only Controller of this identity can do this action");
        _;
    }

    modifier notAdminAddress(address _identity) {
        require (_identity == admin, "This address is fro admin");
        _;
    }
    /*
     *  Events
     */
    event DIDAttributeChanged(
        address indexed identity,
        bytes32 name,
        uint validTo,
        uint previousChange,
        string value
    );
    event OwnershipTransferred(
      address indexed previousOwner,
      address indexed newOwner);

    /**
        @dev 						smart contract initialization (sets the deployer as the initial owner)
        @param _authenticationKey   Admin authentication key
        @param _service             Admin public profile (IPFS Profile)
    */
    constructor (bytes memory _authenticationKey, bytes32  _service){
        admin = msg.sender;
        DIDs[msg.sender] =  DIDDocument(msg.sender,_service, _authenticationKey);
        // the admin is an Issuer
        isIssuer[msg.sender] = true;
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
                   "type": "service",
                   "serviceEndpoint": "www.xsl-labs.io"
                 }
               ]
            }
      @param _identity              User Address (used as Identifier)
      @param _authenticationKey    	Authentication Key (hex format)
      @param _service               Verifable Credential url
    */
    function creatDID (address _identity, bytes32  _service , bytes memory _authenticationKey) external
        onlyAuthorized()
        notNull(_identity)
        identityNotExist(_identity) {

            DIDs[_identity] = DIDDocument(_identity,_service,_authenticationKey);
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
    function creatDIDForIssuer (address _identity, bytes32 _service, bytes memory _authenticationKey) external
        onlyAdmin()
        notNull(_identity)
        identityNotExist(_identity) {

            DIDs[_identity] =  DIDDocument(_identity,_service, _authenticationKey);
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
      @dev Store 				batch of Verifiable credential trace (Hash) associated to issuer address and time
      @param _hashVCs			Verifiable credentialhash (SHA256)
      @param _issuerIdentity	Issuer Address
     */
    function addVCs ( bytes32[] memory _hashVCs, address _issuerIdentity) external
        onlyAdmin()
        issuerExists(_issuerIdentity) {
        for (uint i=0; i<_hashVCs.length ; i++) {
                    VCs[_hashVCs[i]][_issuerIdentity] = block.timestamp;
        }
    }

    /**
      @dev Store 				Verifiable credential IPFS Referance and time  associated to an identity address
      @param _issuerIdentity			Issuer Address
      @param _vcIpfsHash	            Verifiable credentialhash IPFS Referance
     */
    function addPublicVC( address _issuerIdentity, bytes32 _vcIpfsHash) external
    onlyAdmin()
    issuerExists(_issuerIdentity) {
            VCsPublic[_issuerIdentity].push( PublicVC(_vcIpfsHash,block.timestamp));
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
    function setAttribute(address _identity, address _controller, bytes32 name, uint validity , string memory value) internal
        onlyOwner(_identity, _controller) {

            emit DIDAttributeChanged(_identity, name, block.timestamp + validity, changed[_identity], value);
            changed[_identity] = block.number;
    }

    function setAttribute(address _identity, bytes32 name, uint validity, string memory value) public
        identityExists(_identity) {

            setAttribute(_identity, msg.sender, name, validity, value);
    }
    /**
      @dev 					Event emission to add attribute to identity address through off-chain signature with current controller private key
      @param _identity      Identity address
      @param sigV           Recovery identifier
      @param sigR           Signature value R  (message to be signed == 0x19 + 0x00 + Smart Contract Address + Nonce + Identity Address
      @param sigS           Signature value S   + "setAttribute" + name  + validity + value)
      @param name           Attribute name
                                example: Auth/Secp256k1/VeriKey/publicKeyHex (add Authentication Key with Type EcdsaSecp256k1VerificationKey2019 with hex encoded public key)
      @param value          Attribute value
                                ewample: 0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71
      @param validity		Validity period
     */
    function setAttributeSigned(address _identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, uint validity, string memory value) public
        identityExists(_identity) {

            bytes32 hash = keccak256(abi.encodePacked(byte(0x19), byte(0), this, nonce[_identity], _identity, "setAttribute", name, validity, value));
            setAttribute(_identity, checkSignature(_identity, sigV, sigR, sigS, hash), name, validity, value);
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

            emit DIDAttributeChanged(_identity, name, 0, changed[_identity], value);
            changed[_identity] = block.number;
    }

    function revokeAttribute(address _identity, bytes32 name, string memory value) public
        identityExists(_identity) {

            revokeAttribute(_identity, msg.sender, name, value);
    }

    function revokeAttributeSigned(address _identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, string memory value) public
        identityExists(_identity) {

            bytes32 hash = keccak256(abi.encodePacked(byte(0x19), byte(0), this, nonce[_identity], _identity, "revokeAttribute", name, value));
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
    function getDID(address _identity) public view returns(address, bytes32,  bytes memory){
        return (DIDs[_identity].Controller,DIDs[_identity].Service,DIDs[_identity].AuthenticationKey);
    }
    /**
      @dev 					Verifiable Credential trace timestamp retrieval (from verifiable credential hash and issuer address)
      @param _hashVC        Verifiable credential hash
      @param _issuerAddress	Issuer Address
     */
    function getVCtimestamp(bytes32 _hashVC, address _issuerAddress) public view returns(uint){
       return VCs[_hashVC][_issuerAddress];
    }


    /**
            @dev Returns the address of the current admin.
    */
    function owner() public view override returns (address) {
        return admin;
    }


    function transferOwnership(address account)  public override
      onlyAdmin(){
        require(account != address(0), "invalid account");
        emit OwnershipTransferred(admin, account);
        admin = account;
     }
}
