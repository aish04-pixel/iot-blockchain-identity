// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract DeviceIdentity is Ownable2Step {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    struct Device {
        address publicKey;
        bool registered;
        bool active;
        uint256 nonce;
    }

    mapping(bytes32 => Device) private devices;

    error ZeroAddress();
    error AlreadyRegistered();
    error NotRegistered();
    error Revoked();
    error InvalidSignature();

    event DeviceRegistered(bytes32 indexed deviceId, address publicKey);
    event DeviceRevoked(bytes32 indexed deviceId);
    event DeviceKeyRotated(bytes32 indexed deviceId, address newKey);
    event DeviceAuthenticated(bytes32 indexed deviceId, uint256 nonce);

    constructor() Ownable(msg.sender) {}

    function registerDevice(bytes32 deviceId, address publicKey) external onlyOwner {
        if (publicKey == address(0)) revert ZeroAddress();
        if (devices[deviceId].registered) revert AlreadyRegistered();

        devices[deviceId] = Device(publicKey, true, true, 0);
        emit DeviceRegistered(deviceId, publicKey);
    }

    function revokeDevice(bytes32 deviceId) external onlyOwner {
        Device storage d = devices[deviceId];
        if (!d.registered) revert NotRegistered();
        d.active = false;
        emit DeviceRevoked(deviceId);
    }

    function rotateKey(bytes32 deviceId, address newKey) external onlyOwner {
        if (newKey == address(0)) revert ZeroAddress();
        Device storage d = devices[deviceId];
        if (!d.registered) revert NotRegistered();
        d.publicKey = newKey;
        emit DeviceKeyRotated(deviceId, newKey);
    }

    function getNonce(bytes32 deviceId) external view returns (uint256) {
        return devices[deviceId].nonce;
    }

    function checkStatus(bytes32 deviceId)
        external
        view
        returns (bool registered, bool active, address publicKey)
    {
        Device storage d = devices[deviceId];
        return (d.registered, d.active, d.publicKey);
    }

    function authenticateDevice(bytes32 deviceId, bytes calldata signature)
        external
        returns (bool)
    {
        Device storage d = devices[deviceId];
        if (!d.registered) revert NotRegistered();
        if (!d.active) revert Revoked();

        bytes32 digest = keccak256(
            abi.encodePacked(address(this), block.chainid, deviceId, d.nonce)
        ).toEthSignedMessageHash();

        address signer = digest.recover(signature); // reverts on invalid/malleable sig
        if (signer != d.publicKey) revert InvalidSignature();

        emit DeviceAuthenticated(deviceId, d.nonce);
        d.nonce++; // consume the nonce so the signature can't be replayed

        return true;
    }
}