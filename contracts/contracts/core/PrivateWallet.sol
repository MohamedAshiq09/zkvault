// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./ZkVerifier.sol";
import "./CommitmentManager.sol";
import "./StealthRegistry.sol";
import "../interfaces/IPrivateWallet.sol";
import "../interfaces/IZkVerifier.sol";
import "../interfaces/IComplianceModule.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title PrivateWallet
 * @dev Core contract for ZK-powered private wallet functionality
 * @notice Enables private transactions with optional compliance features
 */
contract PrivateWallet is IPrivateWallet, ReentrancyGuard, Ownable, Pausable {
    using SafeMath for uint256;

    // State variables
    IZkVerifier public immutable zkVerifier;
    CommitmentManager public immutable commitmentManager;
    StealthRegistry public immutable stealthRegistry;
    IComplianceModule public complianceModule;

    // Wallet state
    mapping(address => uint256) private _balanceCommitments;
    mapping(bytes32 => bool) private _nullifierHashes;
    mapping(address => uint256) private _nonces;
    
    // Transaction tracking
    mapping(bytes32 => Transaction) private _transactions;
    bytes32[] private _transactionHistory;
    
    // Privacy settings
    mapping(address => PrivacyLevel) private _userPrivacyLevels;
    mapping(address => bool) private _complianceEnabled;

    // Constants
    uint256 public constant MAX_TRANSACTION_AMOUNT = 1000000 * 10**18; // 1M tokens
    uint256 public constant MIN_TRANSACTION_AMOUNT = 1 * 10**15; // 0.001 tokens
    uint256 public constant PROOF_VALIDITY_PERIOD = 1 hours;

    // Events
    event PrivateDeposit(
        address indexed depositor,
        bytes32 indexed commitment,
        uint256 timestamp
    );
    
    event PrivateTransfer(
        bytes32 indexed nullifierHash,
        bytes32 indexed newCommitment,
        address indexed recipient,
        uint256 timestamp
    );
    
    event PrivateWithdrawal(
        bytes32 indexed nullifierHash,
        address indexed recipient,
        uint256 timestamp
    );
    
    event ComplianceStatusChanged(
        address indexed user,
        bool enabled,
        uint256 timestamp
    );

    // Structs
    struct Transaction {
        bytes32 id;
        TransactionType txType;
        bytes32 nullifierHash;
        bytes32 commitment;
        address participant;
        uint256 timestamp;
        bool isCompleted;
    }

    struct ProofData {
        uint256[8] proof;
        uint256[] publicInputs;
        bytes32 nullifierHash;
        bytes32 commitment;
    }

    enum TransactionType { DEPOSIT, TRANSFER, WITHDRAWAL }
    enum PrivacyLevel { TRANSPARENT, SEMI_PRIVATE, FULLY_PRIVATE }

    // Modifiers
    modifier validProof(ProofData memory _proofData) {
        require(
            zkVerifier.verifyProof(
                _proofData.proof,
                _proofData.publicInputs
            ),
            "Invalid ZK proof"
        );
        _;
    }

    modifier nonReusedNullifier(bytes32 _nullifierHash) {
        require(
            !_nullifierHashes[_nullifierHash],
            "Nullifier already used"
        );
        _;
    }

    modifier validAmount(uint256 _amount) {
        require(
            _amount >= MIN_TRANSACTION_AMOUNT && 
            _amount <= MAX_TRANSACTION_AMOUNT,
            "Invalid transaction amount"
        );
        _;
    }

    constructor(
        address _zkVerifier,
        address _commitmentManager,
        address _stealthRegistry
    ) {
        require(_zkVerifier != address(0), "Invalid zkVerifier address");
        require(_commitmentManager != address(0), "Invalid commitmentManager address");
        require(_stealthRegistry != address(0), "Invalid stealthRegistry address");

        zkVerifier = IZkVerifier(_zkVerifier);
        commitmentManager = CommitmentManager(_commitmentManager);
        stealthRegistry = StealthRegistry(_stealthRegistry);
    }

    /**
     * @dev Deposits tokens privately using commitment scheme
     * @param _commitment Pedersen commitment hiding amount and randomness
     * @param _proofData ZK proof data for deposit validity
     */
    function privateDeposit(
        bytes32 _commitment,
        ProofData memory _proofData
    ) 
        external 
        payable 
        nonReentrant 
        whenNotPaused 
        validProof(_proofData)
        validAmount(msg.value)
    {
        require(_commitment != bytes32(0), "Invalid commitment");
        require(!commitmentManager.isCommitmentUsed(_commitment), "Commitment already exists");

        // Store the commitment
        commitmentManager.addCommitment(_commitment, msg.sender);
        _balanceCommitments[msg.sender] = _balanceCommitments[msg.sender].add(msg.value);

        // Create transaction record
        bytes32 txId = keccak256(abi.encodePacked(
            block.timestamp,
            msg.sender,
            _commitment,
            _nonces[msg.sender]++
        ));

        _transactions[txId] = Transaction({
            id: txId,
            txType: TransactionType.DEPOSIT,
            nullifierHash: bytes32(0),
            commitment: _commitment,
            participant: msg.sender,
            timestamp: block.timestamp,
            isCompleted: true
        });

        _transactionHistory.push(txId);

        emit PrivateDeposit(msg.sender, _commitment, block.timestamp);
    }

    /**
     * @dev Transfers tokens privately between users
     * @param _nullifierHash Hash to prevent double spending
     * @param _newCommitment New commitment for recipient
     * @param _recipient Recipient address (can be stealth address)
     * @param _proofData ZK proof data for transfer validity
     */
    function privateTransfer(
        bytes32 _nullifierHash,
        bytes32 _newCommitment,
        address _recipient,
        ProofData memory _proofData
    )
        external
        nonReentrant
        whenNotPaused
        validProof(_proofData)
        nonReusedNullifier(_nullifierHash)
    {
        require(_recipient != address(0), "Invalid recipient");
        require(_newCommitment != bytes32(0), "Invalid new commitment");
        require(!commitmentManager.isCommitmentUsed(_newCommitment), "New commitment already exists");

        // Mark nullifier as used
        _nullifierHashes[_nullifierHash] = true;

        // Add new commitment for recipient
        commitmentManager.addCommitment(_newCommitment, _recipient);

        // Handle stealth address if applicable
        if (stealthRegistry.isStealthAddress(_recipient)) {
            stealthRegistry.registerTransaction(_recipient, _newCommitment);
        }

        // Create transaction record
        bytes32 txId = keccak256(abi.encodePacked(
            block.timestamp,
            msg.sender,
            _recipient,
            _nullifierHash,
            _nonces[msg.sender]++
        ));

        _transactions[txId] = Transaction({
            id: txId,
            txType: TransactionType.TRANSFER,
            nullifierHash: _nullifierHash,
            commitment: _newCommitment,
            participant: _recipient,
            timestamp: block.timestamp,
            isCompleted: true
        });

        _transactionHistory.push(txId);

        // Compliance check if enabled
        if (_complianceEnabled[msg.sender] && address(complianceModule) != address(0)) {
            complianceModule.recordTransaction(msg.sender, _recipient, block.timestamp);
        }

        emit PrivateTransfer(_nullifierHash, _newCommitment, _recipient, block.timestamp);
    }

    /**
     * @dev Withdraws tokens privately from the contract
     * @param _nullifierHash Hash to prevent double spending
     * @param _amount Amount to withdraw
     * @param _proofData ZK proof data for withdrawal validity
     */
    function privateWithdraw(
        bytes32 _nullifierHash,
        uint256 _amount,
        ProofData memory _proofData
    )
        external
        nonReentrant
        whenNotPaused
        validProof(_proofData)
        nonReusedNullifier(_nullifierHash)
        validAmount(_amount)
    {
        require(address(this).balance >= _amount, "Insufficient contract balance");

        // Mark nullifier as used
        _nullifierHashes[_nullifierHash] = true;

        // Update balance commitment (this should be proven in ZK)
        _balanceCommitments[msg.sender] = _balanceCommitments[msg.sender].sub(_amount);

        // Create transaction record
        bytes32 txId = keccak256(abi.encodePacked(
            block.timestamp,
            msg.sender,
            _nullifierHash,
            _amount,
            _nonces[msg.sender]++
        ));

        _transactions[txId] = Transaction({
            id: txId,
            txType: TransactionType.WITHDRAWAL,
            nullifierHash: _nullifierHash,
            commitment: bytes32(0),
            participant: msg.sender,
            timestamp: block.timestamp,
            isCompleted: true
        });

        _transactionHistory.push(txId);

        // Transfer tokens
        (bool success, ) = payable(msg.sender).call{value: _amount}("");
        require(success, "Transfer failed");

        emit PrivateWithdrawal(_nullifierHash, msg.sender, block.timestamp);
    }

    /**
     * @dev Sets user privacy level
     * @param _level Privacy level to set
     */
    function setPrivacyLevel(PrivacyLevel _level) external {
        _userPrivacyLevels[msg.sender] = _level;
    }

    /**
     * @dev Enables or disables compliance for user
     * @param _enabled Whether to enable compliance
     */
    function setComplianceStatus(bool _enabled) external {
        _complianceEnabled[msg.sender] = _enabled;
        emit ComplianceStatusChanged(msg.sender, _enabled, block.timestamp);
    }

    /**
     * @dev Sets compliance module (only owner)
     * @param _complianceModule Address of compliance module
     */
    function setComplianceModule(address _complianceModule) external onlyOwner {
        require(_complianceModule != address(0), "Invalid compliance module");
        complianceModule = IComplianceModule(_complianceModule);
    }

    // View functions
    function isNullifierUsed(bytes32 _nullifierHash) external view returns (bool) {
        return _nullifierHashes[_nullifierHash];
    }

    function getUserPrivacyLevel(address _user) external view returns (PrivacyLevel) {
        return _userPrivacyLevels[_user];
    }

    function isComplianceEnabled(address _user) external view returns (bool) {
        return _complianceEnabled[_user];
    }

    function getTransactionCount() external view returns (uint256) {
        return _transactionHistory.length;
    }

    function getTransaction(bytes32 _txId) external view returns (Transaction memory) {
        return _transactions[_txId];
    }

    function getUserNonce(address _user) external view returns (uint256) {
        return _nonces[_user];
    }

    // Emergency functions
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function emergencyWithdraw() external onlyOwner {
        (bool success, ) = payable(owner()).call{value: address(this).balance}("");
        require(success, "Emergency withdrawal failed");
    }

    // Receive function
    receive() external payable {
        // Allow contract to receive ETH
    }
}

// SafeMath library for older Solidity versions
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        return a - b;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0;
        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0, "SafeMath: division by zero");
        return a / b;
    }
}