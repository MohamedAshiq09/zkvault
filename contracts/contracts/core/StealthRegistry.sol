// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title StealthRegistry
 * @dev Manages stealth addresses for private transactions
 * @notice Enables users to generate and manage stealth addresses for enhanced privacy
 */
contract StealthRegistry is Ownable, ReentrancyGuard {
    
    // Stealth address structure
    struct StealthAddress {
        address stealthAddr;        // The stealth address
        address owner;             // Owner of the stealth address
        uint256 timestamp;         // Creation timestamp
        bool isActive;            // Whether address is active
        bytes32 sharedSecret;     // Shared secret for key derivation
        uint256 viewKey;          // View key for scanning
    }

    // Stealth transaction structure
    struct StealthTransaction {
        bytes32 txHash;           // Transaction hash
        address stealthAddr;      // Stealth address used
        bytes32 commitment;       // Associated commitment
        uint256 timestamp;        // Transaction timestamp
        bool isSpent;            // Whether transaction is spent
    }

    // State variables
    mapping(address => StealthAddress) private _stealthAddresses;
    mapping(address => address) private _stealthToOwner;
    mapping(address => address[]) private _userStealthAddresses;
    mapping(address => StealthTransaction[]) private _stealthTransactions;
    mapping(bytes32 => StealthTransaction) private _transactionRegistry;
    
    // Public key registry for stealth address generation
    mapping(address => uint256[2]) private _publicKeys;
    mapping(address => bool) private _publicKeyRegistered;
    
    // Announcement system for stealth payments
    mapping(address => bytes32[]) private _announcements;
    bytes32[] private _globalAnnouncements;
    
    // Constants
    uint256 public constant SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 public constant MAX_STEALTH_ADDRESSES = 100;

    // Events
    event StealthAddressGenerated(
        address indexed owner,
        address indexed stealthAddress,
        uint256 timestamp
    );
    
    event StealthTransactionRegistered(
        address indexed stealthAddress,
        bytes32 indexed commitment,
        bytes32 indexed txHash,
        uint256 timestamp
    );
    
    event StealthPaymentAnnouncement(
        address indexed recipient,
        bytes32 indexed ephemeralPublicKey,
        bytes32 indexed announcement,
        uint256 timestamp
    );
    
    event PublicKeyRegistered(
        address indexed user,
        uint256[2] publicKey,
        uint256 timestamp
    );

    // Modifiers
    modifier validAddress(address _addr) {
        require(_addr != address(0), "Invalid address");
        _;
    }

    modifier onlyStealthOwner(address _stealthAddr) {
        require(_stealthToOwner[_stealthAddr] == msg.sender, "Not stealth address owner");
        _;
    }

    modifier publicKeyRequired(address _user) {
        require(_publicKeyRegistered[_user], "Public key not registered");
        _;
    }

    constructor() {
        // Initialize contract
    }

    /**
     * @dev Registers a public key for stealth address generation
     * @param _publicKey The user's public key [x, y] coordinates
     */
    function registerPublicKey(uint256[2] memory _publicKey) external {
        require(_publicKey[0] != 0 && _publicKey[1] != 0, "Invalid public key");
        require(_publicKey[0] < SECP256K1_ORDER && _publicKey[1] < SECP256K1_ORDER, "Public key out of range");
        
        _publicKeys[msg.sender] = _publicKey;
        _publicKeyRegistered[msg.sender] = true;
        
        emit PublicKeyRegistered(msg.sender, _publicKey, block.timestamp);
    }

    /**
     * @dev Generates a stealth address for a user
     * @param _recipient The recipient's address (must have registered public key)
     * @param _ephemeralPrivateKey Ephemeral private key for ECDH
     * @return stealthAddress The generated stealth address
     * @return sharedSecret The shared secret for the recipient
     */
    function generateStealthAddress(
        address _recipient,
        uint256 _ephemeralPrivateKey
    ) 
        external 
        validAddress(_recipient) 
        publicKeyRequired(_recipient) 
        returns (address stealthAddress, bytes32 sharedSecret) 
    {
        require(_ephemeralPrivateKey != 0 && _ephemeralPrivateKey < SECP256K1_ORDER, "Invalid ephemeral private key");
        require(_userStealthAddresses[_recipient].length < MAX_STEALTH_ADDRESSES, "Max stealth addresses reached");

        // Get recipient's public key
        uint256[2] memory recipientPubKey = _publicKeys[_recipient];
        
        // Compute shared secret using ECDH
        // sharedSecret = ephemeralPrivateKey * recipientPubKey
        sharedSecret = _computeSharedSecret(_ephemeralPrivateKey, recipientPubKey);
        
        // Derive stealth private key
        uint256 stealthPrivateKey = _deriveStealthPrivateKey(sharedSecret, _recipient);
        
        // Generate stealth address from stealth private key
        stealthAddress = _privateKeyToAddress(stealthPrivateKey);
        
        // Store stealth address info
        _stealthAddresses[stealthAddress] = StealthAddress({
            stealthAddr: stealthAddress,
            owner: _recipient,
            timestamp: block.timestamp,
            isActive: true,
            sharedSecret: sharedSecret,
            viewKey: uint256(keccak256(abi.encodePacked(sharedSecret, "view_key")))
        });
        
        _stealthToOwner[stealthAddress] = _recipient;
        _userStealthAddresses[_recipient].push(stealthAddress);
        
        // Create announcement for recipient to detect the payment
        bytes32 ephemeralPubKeyHash = keccak256(abi.encodePacked(_ephemeralPrivateKey));
        _announcements[_recipient].push(ephemeralPubKeyHash);
        _globalAnnouncements.push(ephemeralPubKeyHash);
        
        emit StealthAddressGenerated(_recipient, stealthAddress, block.timestamp);
        emit StealthPaymentAnnouncement(_recipient, ephemeralPubKeyHash, sharedSecret, block.timestamp);
        
        return (stealthAddress, sharedSecret);
    }

    /**
     * @dev Registers a transaction to a stealth address
     * @param _stealthAddr The stealth address
     * @param _commitment The commitment associated with the transaction
     */
    function registerTransaction(
        address _stealthAddr,
        bytes32 _commitment
    ) external validAddress(_stealthAddr) {
        require(isStealthAddress(_stealthAddr), "Not a registered stealth address");
        require(_commitment != bytes32(0), "Invalid commitment");
        
        bytes32 txHash = keccak256(abi.encodePacked(
            block.timestamp,
            _stealthAddr,
            _commitment,
            msg.sender
        ));
        
        StealthTransaction memory stealthTx = StealthTransaction({
            txHash: txHash,
            stealthAddr: _stealthAddr,
            commitment: _commitment,
            timestamp: block.timestamp,
            isSpent: false
        });
        
        _stealthTransactions[_stealthAddr].push(stealthTx);
        _transactionRegistry[txHash] = stealthTx;
        
        emit StealthTransactionRegistered(_stealthAddr, _commitment, txHash, block.timestamp);
    }

    /**
     * @dev Scans for stealth transactions belonging to a user
     * @param _user The user address to scan for
     * @param _startIndex Starting index for scanning
     * @param _count Number of announcements to scan
     * @return stealthAddresses Array of detected stealth addresses
     * @return transactions Array of associated transactions
     */
    function scanStealthTransactions(
        address _user,
        uint256 _startIndex,
        uint256 _count
    ) 
        external 
        view 
        publicKeyRequired(_user) 
        returns (
            address[] memory stealthAddresses,
            StealthTransaction[] memory transactions
        ) 
    {
        require(_startIndex < _globalAnnouncements.length, "Start index out of range");
        
        uint256 endIndex = _startIndex + _count;
        if (endIndex > _globalAnnouncements.length) {
            endIndex = _globalAnnouncements.length;
        }
        
        address[] memory tempAddresses = new address[](endIndex - _startIndex);
        StealthTransaction[] memory tempTransactions = new StealthTransaction[](endIndex - _startIndex);
        uint256 foundCount = 0;
        
        uint256[2] memory userPubKey = _publicKeys[_user];
        
        for (uint256 i = _startIndex; i < endIndex; i++) {
            bytes32 announcement = _globalAnnouncements[i];
            
            // Try to reconstruct stealth address
            address potentialStealth = _reconstructStealthAddress(announcement, userPubKey, _user);
            
            if (_stealthToOwner[potentialStealth] == _user) {
                tempAddresses[foundCount] = potentialStealth;
                
                // Get latest transaction for this stealth address
                StealthTransaction[] memory stealthTxs = _stealthTransactions[potentialStealth];
                if (stealthTxs.length > 0) {
                    tempTransactions[foundCount] = stealthTxs[stealthTxs.length - 1];
                }
                
                foundCount++;
            }
        }
        
        // Resize arrays to actual found count
        stealthAddresses = new address[](foundCount);
        transactions = new StealthTransaction[](foundCount);
        
        for (uint256 i = 0; i < foundCount; i++) {
            stealthAddresses[i] = tempAddresses[i];
            transactions[i] = tempTransactions[i];
        }
        
        return (stealthAddresses, transactions);
    }

    /**
     * @dev Computes shared secret using ECDH
     * @param _ephemeralPrivateKey Ephemeral private key
     * @param _publicKey Recipient's public key
     * @return Shared secret
     */
    function _computeSharedSecret(
        uint256 _ephemeralPrivateKey,
        uint256[2] memory _publicKey
    ) private pure returns (bytes32) {
        // Simplified ECDH computation
        // In production, use proper elliptic curve multiplication
        bytes32 secret = keccak256(abi.encodePacked(
            _ephemeralPrivateKey,
            _publicKey[0],
            _publicKey[1]
        ));
        
        return secret;
    }

    /**
     * @dev Derives stealth private key from shared secret
     * @param _sharedSecret The shared secret
     * @param _recipient The recipient address
     * @return Stealth private key
     */
    function _deriveStealthPrivateKey(
        bytes32 _sharedSecret,
        address _recipient
    ) private pure returns (uint256) {
        bytes32 derivedKey = keccak256(abi.encodePacked(
            _sharedSecret,
            _recipient,
            "stealth_key"
        ));
        
        return uint256(derivedKey) % SECP256K1_ORDER;
    }

    /**
     * @dev Converts private key to address
     * @param _privateKey The private key
     * @return The corresponding address
     */
    function _privateKeyToAddress(uint256 _privateKey) private pure returns (address) {
        // Simplified conversion
        // In production, use proper elliptic curve operations
        bytes32 publicKeyHash = keccak256(abi.encodePacked(_privateKey, "pubkey"));
        return address(uint160(uint256(publicKeyHash)));
    }

    /**
     * @dev Reconstructs stealth address from announcement
     * @param _announcement The payment announcement
     * @param _userPubKey User's public key
     * @param _user User's address
     * @return Reconstructed stealth address
     */
    function _reconstructStealthAddress(
        bytes32 _announcement,
        uint256[2] memory _userPubKey,
        address _user
    ) private pure returns (address) {
        // Simplified reconstruction
        bytes32 sharedSecret = keccak256(abi.encodePacked(
            _announcement,
            _userPubKey[0],
            _userPubKey[1]
        ));
        
        uint256 stealthPrivateKey = uint256(keccak256(abi.encodePacked(
            sharedSecret,
            _user,
            "stealth_key"
        ))) % SECP256K1_ORDER;
        
        bytes32 publicKeyHash = keccak256(abi.encodePacked(stealthPrivateKey, "pubkey"));
        return address(uint160(uint256(publicKeyHash)));
    }

    // View functions
    function isStealthAddress(address _addr) public view returns (bool) {
        return _stealthAddresses[_addr].owner != address(0);
    }

    function getStealthAddressInfo(address _stealthAddr) external view returns (StealthAddress memory) {
        require(isStealthAddress(_stealthAddr), "Not a stealth address");
        return _stealthAddresses[_stealthAddr];
    }

    function getUserStealthAddresses(address _user) external view returns (address[] memory) {
        return _userStealthAddresses[_user];
    }

    function getStealthTransactions(address _stealthAddr) external view returns (StealthTransaction[] memory) {
        return _stealthTransactions[_stealthAddr];
    }

    function getUserPublicKey(address _user) external view returns (uint256[2] memory) {
        require(_publicKeyRegistered[_user], "Public key not registered");
        return _publicKeys[_user];
    }

    function isPublicKeyRegistered(address _user) external view returns (bool) {
        return _publicKeyRegistered[_user];
    }

    function getAnnouncementCount() external view returns (uint256) {
        return _globalAnnouncements.length;
    }

    function getUserAnnouncementCount(address _user) external view returns (uint256) {
        return _announcements[_user].length;
    }

    // Admin functions
    function deactivateStealthAddress(address _stealthAddr) external onlyStealthOwner(_stealthAddr) {
        _stealthAddresses[_stealthAddr].isActive = false;
    }

    function reactivateStealthAddress(address _stealthAddr) external onlyStealthOwner(_stealthAddr) {
        _stealthAddresses[_stealthAddr].isActive = true;
    }

    function emergencyDeactivateAddress(address _stealthAddr) external onlyOwner {
        _stealthAddresses[_stealthAddr].isActive = false;
    }
}