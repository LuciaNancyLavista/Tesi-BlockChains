// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title TrustedIssuers
 * @dev A whitelist of trusted institutional Issuers, managed by an administrator.
 */
contract TrustedIssuers {
    address public admin;
    mapping(address => bool) private trustedIssuers;

    event IssuerAdded(address indexed issuer, uint256 timestamp);
    event IssuerRemoved(address indexed issuer, uint256 timestamp);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function addIssuer(address _issuer) public onlyAdmin {
        trustedIssuers[_issuer] = true;
        emit IssuerAdded(_issuer, block.timestamp);
    }

    function removeIssuer(address _issuer) public onlyAdmin {
        trustedIssuers[_issuer] = false;
        emit IssuerRemoved(_issuer, block.timestamp);
    }

    function isTrusted(address _issuer) public view returns (bool) {
        return trustedIssuers[_issuer];
    }
}
