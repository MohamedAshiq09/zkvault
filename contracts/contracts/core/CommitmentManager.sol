// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title CommitmentManager
 * @dev Manages Pedersen commitments for private balances and transactions
 * @notice Handles commitment creation, verification, and Merkle tree operations
 */
contract CommitmentManager is Ownable, ReentrancyGuard {
    
    // Commitment structure
    struct Commitment {
        bytes32 hash;           // The commitment hash
        address owner;          // Owner of the commitment
        uint256 timestamp;      // When commitment was created
        bool isUsed;           // Whether commitment has been spent
        uint256 leafIndex;     // Index in Merkle tree
    }

    // Merkle tree parameters
    uint256 public constant TREE_DEPTH = 20;
    uint256 public constant MAX_LEAVES = 2**TREE_DEPTH;
    
    // State variables
    mapping(bytes32 => Commitment) private _commitments;
    mapping(address => bytes32[]) private _userCommitments;
    mapping(uint256 => bytes32) private _merkleTree;
    
    bytes32[] private _leaves;
    uint256 private _nextLeafIndex;
    bytes32 private _merkleRoot;
    
    // Commitment validation
    mapping(bytes32 => bool) private _validCommitments;
    mapping(address => uint256) private _commitmentCounts;
    
    // Constants for Pedersen commitment
    uint256 public constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant GENERATOR_X = 1; // Placeholder - use actual generator
    uint256 public constant GENERATOR_Y = 2; // Placeholder - use actual generator
    
    // Events
    event CommitmentAdded(
        bytes32 indexed commitment,
        address indexed owner,
        uint256 indexed leafIndex,
        uint256 timestamp
    );
    
    event CommitmentSpent(
        bytes32 indexed commitment,
        address indexed spender,
        uint256 timestamp
    );
    
    event MerkleRootUpdated(
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        uint256 timestamp
    );