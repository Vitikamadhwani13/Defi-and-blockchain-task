// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ChainProof
 * @notice - optimized on-chain credential and trust system.
 * Credentials are non-transferable because they are stored directly against
 * recipient addresses and no transfer functionality exists.
 */
contract ChainProof {
    address public immutable admin;

    enum Category { Learning, Leadership, Contribution, Mentorship }
    enum ReputationTier { Bronze, Silver, Gold, Platinum }
    enum EligibilityStatus { NotEligible, ConditionallyEligible, FullyEligible }
    enum VerificationStatus { Pending, Verified, Revoked }

    struct Credential {
        string title;
        uint8 level; // 1 basic, 2 intermediate, 3 advanced
        uint256 issuedAt;
        address issuedBy;
        Category category;
        bool active;
        VerificationStatus status;
    }

    error NotAdmin();
    error NotIssuer();
    error InvalidAddress();
    error InvalidLevel();
    error EmptyTitle();
    error DuplicateCredential();
    error CredentialNotFound();
    error InsufficientTrustScore(uint256 current, uint256 required);

    event IssuerAdded(address indexed issuer);
    event IssuerRemoved(address indexed issuer);
    event CredentialIssued(address indexed user,string title,uint8 level,address indexed issuer);
    event CredentialRevoked(address indexed user,uint256 credentialIndex);

    mapping(address => bool) public authorizedIssuers;
    mapping(address => Credential[]) private credentials;
    mapping(address => mapping(bytes32 => bool)) private credentialExists;
    mapping(address => uint256) public totalCredentials;

    uint256 public constant ACCESS_THRESHOLD = 100;

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier onlyAuthorizedIssuer() {
        if (msg.sender != admin && !authorizedIssuers[msg.sender]) revert NotIssuer();
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function addIssuer(address issuer) external onlyAdmin {
        if (issuer == address(0)) revert InvalidAddress();
        authorizedIssuers[issuer] = true;
        emit IssuerAdded(issuer);
    }

    function removeIssuer(address issuer) external onlyAdmin {
        authorizedIssuers[issuer] = false;
        emit IssuerRemoved(issuer);
    }

    function issueCredential(
        address recipient,
        string memory title,
        uint8 level,
        Category category
    ) external onlyAuthorizedIssuer {
        if (recipient == address(0)) revert InvalidAddress();
        if (bytes(title).length == 0) revert EmptyTitle();
        if (level < 1 || level > 3) revert InvalidLevel();

        bytes32 titleHash = keccak256(bytes(title));

        // Duplicate credentials are rejected to prevent trust-score inflation.
        if (credentialExists[recipient][titleHash]) revert DuplicateCredential();

        credentials[recipient].push(
            Credential({
                title: title,
                level: level,
                issuedAt: block.timestamp,
                issuedBy: msg.sender,
                category: category,
                active: true,
                status: VerificationStatus.Verified
            })
        );

        credentialExists[recipient][titleHash] = true;
        totalCredentials[recipient]++;

        emit CredentialIssued(recipient, title, level, msg.sender);
    }

    function revokeCredential(address user, uint256 index) external onlyAdmin {
        if (index >= credentials[user].length) revert CredentialNotFound();

        credentials[user][index].active = false;
        credentials[user][index].status = VerificationStatus.Revoked;

        emit CredentialRevoked(user, index);
    }

    function getCredentials(address user)
        external
        view
        returns (Credential[] memory)
    {
        return credentials[user];
    }

    function getCredentialCount(address user)
        external
        view
        returns (uint256)
    {
        return totalCredentials[user];
    }

    /**
     * Trust Score Formula:
     * Level 1 = 10, Level 2 = 25, Level 3 = 50.
     * Category multipliers:
     * Learning 1.00, Contribution 1.10, Mentorship 1.15, Leadership 1.20.
     * Rewards both quantity and quality.
     */
    function getTrustScore(address user) public view returns (uint256 score) {
        Credential[] memory creds = credentials[user];

        for (uint256 i = 0; i < creds.length; i++) {
            if (!creds[i].active || creds[i].status != VerificationStatus.Verified) {
                continue;
            }

            uint256 base;
            if (creds[i].level == 1) base = 10;
            else if (creds[i].level == 2) base = 25;
            else base = 50;

            uint256 multiplier = 100;
            if (creds[i].category == Category.Contribution) multiplier = 110;
            else if (creds[i].category == Category.Mentorship) multiplier = 115;
            else if (creds[i].category == Category.Leadership) multiplier = 120;

            score += (base * multiplier) / 100;
        }
    }

    function getReputationTier(address user)
        public
        view
        returns (ReputationTier)
    {
        uint256 score = getTrustScore(user);

        if (score >= 200) return ReputationTier.Platinum;
        if (score >= 100) return ReputationTier.Gold;
        if (score >= 50) return ReputationTier.Silver;
        return ReputationTier.Bronze;
    }

    function getEligibilityStatus(address user)
        public
        view
        returns (EligibilityStatus)
    {
        uint256 score = getTrustScore(user);

        if (score >= 100) return EligibilityStatus.FullyEligible;
        if (score >= 50) return EligibilityStatus.ConditionallyEligible;
        return EligibilityStatus.NotEligible;
    }

    function _activeCredentialCount(address user)
        internal
        view
        returns (uint256 count)
    {
        Credential[] memory creds = credentials[user];
        for (uint256 i = 0; i < creds.length; i++) {
            if (creds[i].active && creds[i].status == VerificationStatus.Verified) {
                count++;
            }
        }
    }

    function accessGranted() external view returns (bool) {
        uint256 score = getTrustScore(msg.sender);
        uint256 activeCount = _activeCredentialCount(msg.sender);

        if (score < ACCESS_THRESHOLD || activeCount < 2) {
            revert InsufficientTrustScore(score, ACCESS_THRESHOLD);
        }

        return true;
    }

    function checkEligibility(address user)
        external
        view
        returns (
            uint256 trustScore,
            ReputationTier tier,
            EligibilityStatus status,
            uint256 activeCredentials,
            uint256 requiredScore,
            bool eligible
        )
    {
        trustScore = getTrustScore(user);
        tier = getReputationTier(user);
        status = getEligibilityStatus(user);
        activeCredentials = _activeCredentialCount(user);
        requiredScore = ACCESS_THRESHOLD;
        eligible = (trustScore >= ACCESS_THRESHOLD && activeCredentials >= 2);
    }
}