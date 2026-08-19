// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title RevocationRegistry
 * @dev Stores the URI of the Token Status List (IETF SD-JWT bitstring) for each Issuer.
 */
contract RevocationRegistry {
    mapping(address => string) private issuerStatusListURIs;

    event StatusListURIPublished(address indexed issuer, string uri, uint256 timestamp);

    function publishStatusListURI(string memory _uri) public {
        issuerStatusListURIs[msg.sender] = _uri;
        emit StatusListURIPublished(msg.sender, _uri, block.timestamp);
    }

    function getStatusListURI(address _issuer) public view returns (string memory) {
        require(bytes(issuerStatusListURIs[_issuer]).length > 0, "No status list published for this issuer");
        return issuerStatusListURIs[_issuer];
    }
}
