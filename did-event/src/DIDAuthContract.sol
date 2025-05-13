// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DIDAuthContract {
    // --- Event definitions ---
    event DIDRegistered(bytes32 indexed didHash, address indexed controller, uint256 createdAt);
    event TrustedIssuerRegistered(bytes32 indexed issuerDidHash, bytes32 schemaId, uint256 registeredAt);
    event CredentialIssued(bytes32 indexed vcHash, bytes32 indexed issuerDidHash, bytes32 schemaId, uint256 issuedAt);
    event CredentialRevoked(bytes32 indexed vcHash, bytes32 indexed issuerDidHash, uint256 revokedAt, string reason);
    event DIDDeactivated(bytes32 indexed didHash, uint256 deactivatedAt);
    event CredentialVerified(bytes32 indexed vcHash, bytes32 indexed verifierDidHash, uint256 verifiedAt);

    // --- State variables ---
    mapping(bytes32 => address) public didControllers;
    mapping(bytes32 => bool) public trustedIssuers;
    mapping(bytes32 => bool) public revokedCredentials;

    // --- Register DID ---
    function registerDID(string calldata did) external {
        bytes32 didHash = keccak256(abi.encodePacked(did));
        require(didControllers[didHash] == address(0), "DID already registered");

        didControllers[didHash] = msg.sender;
        emit DIDRegistered(didHash, msg.sender, block.timestamp);
    }

    // --- Register Trusted Issuer ---
    function registerTrustedIssuer(string calldata issuerDID, bytes32 schemaId) external {
        bytes32 didHash = keccak256(abi.encodePacked(issuerDID));
        require(didControllers[didHash] == msg.sender, "Only controller can register issuer");

        trustedIssuers[didHash] = true;
        emit TrustedIssuerRegistered(didHash, schemaId, block.timestamp);
    }

    // --- Issue VC ---
    function issueCredential(string calldata vcData, string calldata issuerDID, bytes32 schemaId) external {
        bytes32 issuerDidHash = keccak256(abi.encodePacked(issuerDID));
        require(trustedIssuers[issuerDidHash], "Issuer not trusted");

        bytes32 vcHash = keccak256(abi.encodePacked(vcData));
        emit CredentialIssued(vcHash, issuerDidHash, schemaId, block.timestamp);
    }

    // --- Revoke VC ---
    function revokeCredential(string calldata vcData, string calldata issuerDID, string calldata reason) external {
        bytes32 issuerDidHash = keccak256(abi.encodePacked(issuerDID));
        require(trustedIssuers[issuerDidHash], "Issuer not trusted");

        bytes32 vcHash = keccak256(abi.encodePacked(vcData));
        revokedCredentials[vcHash] = true;
        emit CredentialRevoked(vcHash, issuerDidHash, block.timestamp, reason);
    }

    // --- Deactivate DID ---
    function deactivateDID(string calldata did) external {
        bytes32 didHash = keccak256(abi.encodePacked(did));
        require(didControllers[didHash] == msg.sender, "Only controller can deactivate");

        delete didControllers[didHash];
        emit DIDDeactivated(didHash, block.timestamp);
    }

    // --- Log VC Verification ---
    function logCredentialVerification(string calldata vcData, string calldata verifierDID) external {
        bytes32 vcHash = keccak256(abi.encodePacked(vcData));
        bytes32 verifierDidHash = keccak256(abi.encodePacked(verifierDID));

        require(!revokedCredentials[vcHash], "VC has been revoked");
        emit CredentialVerified(vcHash, verifierDidHash, block.timestamp);
    }
}

contract DIDAuthTest {
    DIDAuthContract public auth;

    constructor(address _auth) {
        auth = DIDAuthContract(_auth);
    }

    function simulateFlow() external {
        string memory issuerDID = "did:example:issuer";
        string memory userDID = "did:example:user";
        string memory vcData = "{subject:did:example:user,degree:ComputerScience}";
        bytes32 schemaId = keccak256("UniversityCredential");

        auth.registerDID(issuerDID);
        auth.registerTrustedIssuer(issuerDID, schemaId);
        auth.issueCredential(vcData, issuerDID, schemaId);
        auth.logCredentialVerification(vcData, "did:example:verifier");
        auth.revokeCredential(vcData, issuerDID, "Graduated");
        auth.deactivateDID(issuerDID);
    }
}
