// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PolicyRegistry
 * @dev Allows Relying Parties to publish their required access policies on-chain.
 */
contract PolicyRegistry {
    // RP address => Policy description/JSON
    mapping(address => string) private policies;

    event PolicyPublished(address indexed rp, string policy, uint256 timestamp);

    function publishPolicy(string memory _policy) public {
        policies[msg.sender] = _policy;
        emit PolicyPublished(msg.sender, _policy, block.timestamp);
    }

    function getPolicy(address _rp) public view returns (string memory) {
        require(bytes(policies[_rp]).length > 0, "No policy published for this RP");
        return policies[_rp];
    }
}
