// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract DIDRegistry {
    struct DIDDocument {
        address owner;
        string publicKey; // Hex string or JWK depending on implementation
        string serviceEndpoint;
        uint256 createdAt;
        uint256 updatedAt;
        bool active;
    }

    mapping(string => DIDDocument) private dids;
    mapping(address => string) private ownerToDid;

    event DIDRegistered(address indexed owner, string did, string publicKey, uint256 timestamp);
    event DIDUpdated(address indexed owner, string did, string publicKey, uint256 timestamp);
    event DIDRevoked(address indexed owner, string did, uint256 timestamp);

    function registerDID(string memory _did, string memory _publicKey, string memory _serviceEndpoint) public {
        require(bytes(ownerToDid[msg.sender]).length == 0, "Address already owns a DID");
        require(dids[_did].owner == address(0), "DID already registered");

        dids[_did] = DIDDocument({
            owner: msg.sender,
            publicKey: _publicKey,
            serviceEndpoint: _serviceEndpoint,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            active: true
        });

        ownerToDid[msg.sender] = _did;

        emit DIDRegistered(msg.sender, _did, _publicKey, block.timestamp);
    }

    function updateDID(string memory _newPublicKey, string memory _newEndpoint) public {
        string memory _did = ownerToDid[msg.sender];
        require(bytes(_did).length > 0, "No DID registered for this address");
        require(dids[_did].active, "DID is revoked");

        dids[_did].publicKey = _newPublicKey;
        dids[_did].serviceEndpoint = _newEndpoint;
        dids[_did].updatedAt = block.timestamp;

        emit DIDUpdated(msg.sender, _did, _newPublicKey, block.timestamp);
    }

    function revokeDID() public {
        string memory _did = ownerToDid[msg.sender];
        require(bytes(_did).length > 0, "No DID registered for this address");
        require(dids[_did].active, "DID is already revoked");

        dids[_did].active = false;
        dids[_did].updatedAt = block.timestamp;

        emit DIDRevoked(msg.sender, _did, block.timestamp);
    }

    function resolveDID(string memory _did) public view returns (DIDDocument memory) {
        require(dids[_did].owner != address(0), "DID not found");
        return dids[_did];
    }

    function isActive(string memory _did) public view returns (bool) {
        if (dids[_did].owner == address(0)) {
            return false;
        }
        return dids[_did].active;
    }
}
