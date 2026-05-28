// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract OnChainPermissionScopeManagerV1 {

    struct PermissionScope {
        bytes32 scopeHash;
        bool active;
        uint64 grantedAt;
        uint64 expiresAt;
    }

    // user => app => scopes
    mapping(address => mapping(address => PermissionScope[]))
        public permissions;

    event ScopeGranted(
        address indexed user,
        address indexed app,
        uint256 indexed scopeId,
        bytes32 scopeHash,
        uint64 expiresAt
    );

    event ScopeRevoked(
        address indexed user,
        address indexed app,
        uint256 indexed scopeId
    );

    event ScopeRotated(
        address indexed user,
        address indexed app,
        uint256 indexed scopeId,
        bytes32 newScopeHash
    );

    function grantScope(
        address app,
        string calldata rawScope,
        uint64 durationSeconds
    ) external {

        require(
            app != address(0),
            "Invalid app"
        );

        require(
            durationSeconds > 0,
            "Invalid duration"
        );

        bytes32 h = keccak256(
            abi.encodePacked(rawScope)
        );

        permissions[msg.sender][app].push(
            PermissionScope({
                scopeHash: h,
                active: true,
                grantedAt: uint64(block.timestamp),
                expiresAt: uint64(
                    block.timestamp + durationSeconds
                )
            })
        );

        emit ScopeGranted(
            msg.sender,
            app,
            permissions[msg.sender][app].length - 1,
            h,
            uint64(block.timestamp + durationSeconds)
        );
    }

    function revokeScope(
        address app,
        uint256 scopeId
    ) external {

        PermissionScope storage s =
            permissions[msg.sender][app][scopeId];

        require(
            s.active,
            "Already inactive"
        );

        s.active = false;

        emit ScopeRevoked(
            msg.sender,
            app,
            scopeId
        );
    }

    function rotateScope(
        address app,
        uint256 scopeId,
        string calldata newRawScope
    ) external {

        PermissionScope storage s =
            permissions[msg.sender][app][scopeId];

        require(
            s.active,
            "Inactive scope"
        );

        require(
            block.timestamp < s.expiresAt,
            "Expired scope"
        );

        bytes32 newHash = keccak256(
            abi.encodePacked(newRawScope)
        );

        s.scopeHash = newHash;

        emit ScopeRotated(
            msg.sender,
            app,
            scopeId,
            newHash
        );
    }

    function verifyScope(
        address user,
        address app,
        uint256 scopeId,
        string calldata rawScope
    )
        external
        view
        returns (bool)
    {

        PermissionScope storage s =
            permissions[user][app][scopeId];

        if (!s.active) {
            return false;
        }

        if (block.timestamp >= s.expiresAt) {
            return false;
        }

        return (
            s.scopeHash ==
            keccak256(
                abi.encodePacked(rawScope)
            )
        );
    }

    function getScopeCount(
        address user,
        address app
    )
        external
        view
        returns (uint256)
    {
        return permissions[user][app].length;
    }
}
