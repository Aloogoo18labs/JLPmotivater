// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title JLPmotivater — on-chain execution vault with signed signals
/// @notice A mainnet-safe execution surface for off-chain “AI” signals: the contract never fabricates prices;
///         it only verifies authorized signatures and executes swaps through a configured DEX router.
/// @dev No deposits of native ETH are accepted. ERC20-only vault.

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IERC20Metadata is IERC20 {
    function decimals() external view returns (uint8);
    function symbol() external view returns (string memory);
    function name() external view returns (string memory);
}

interface IUniswapV2Factory {
    function getPair(address tokenA, address tokenB) external view returns (address pair);
}

interface IUniswapV2Pair {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

interface IUniswapV2Router02 {
    function factory() external view returns (address);
    function WETH() external view returns (address);

    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);

    function getAmountsOut(uint256 amountIn, address[] calldata path) external view returns (uint256[] memory amounts);
}

library JLPmAddress {
    function isContract(address a) internal view returns (bool) {
        return a.code.length != 0;
    }

    function requireNotZero(address a) internal pure {
        require(a != address(0), "JLPm:zero");
    }
}

library JLPmMath {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }

    function absDiff(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? (a - b) : (b - a);
    }
}

library JLPmERC20 {
    error JLPmERC20_CallFailed();
    error JLPmERC20_BadReturn();

    function _callOptionalReturn(address token, bytes memory data) private {
        (bool ok, bytes memory ret) = token.call(data);
        if (!ok) revert JLPmERC20_CallFailed();
        if (ret.length == 0) return;
        if (ret.length == 32) {
            uint256 v;
            assembly {
                v := mload(add(ret, 0x20))
            }
            if (v != 1) revert JLPmERC20_BadReturn();
            return;
        }
        revert JLPmERC20_BadReturn();
    }

    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        _callOptionalReturn(address(token), abi.encodeWithSelector(IERC20.transfer.selector, to, amount));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        _callOptionalReturn(address(token), abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount));
    }

    function safeApprove(IERC20 token, address spender, uint256 amount) internal {
        _callOptionalReturn(address(token), abi.encodeWithSelector(IERC20.approve.selector, spender, amount));
    }
}

abstract contract JLPmReentrancyGuard {
    uint256 private _status;

    error JLPm_ReentrantCall();

    constructor() {
        _status = 1;
    }

    modifier nonReentrant() {
        if (_status != 1) revert JLPm_ReentrantCall();
        _status = 2;
        _;
        _status = 1;
    }
}

abstract contract JLPmPausable {
    bool private _paused;

    error JLPm_Paused();
    error JLPm_NotPaused();

    event JLPmPaused(address indexed by);
    event JLPmUnpaused(address indexed by);

    modifier whenNotPaused() {
        if (_paused) revert JLPm_Paused();
        _;
    }

    modifier whenPaused() {
        if (!_paused) revert JLPm_NotPaused();
        _;
    }

    function paused() public view returns (bool) {
        return _paused;
    }

    function _pause() internal whenNotPaused {
        _paused = true;
        emit JLPmPaused(msg.sender);
    }

    function _unpause() internal whenPaused {
        _paused = false;
        emit JLPmUnpaused(msg.sender);
    }
}

abstract contract JLPmAccess {
    mapping(bytes32 => mapping(address => bool)) private _role;

    bytes32 internal constant ROLE_ADMIN = keccak256("JLPmotivater.ROLE_ADMIN");
    bytes32 internal constant ROLE_KEEPER = keccak256("JLPmotivater.ROLE_KEEPER");
    bytes32 internal constant ROLE_SIGNALER = keccak256("JLPmotivater.ROLE_SIGNALER");
    bytes32 internal constant ROLE_RISK = keccak256("JLPmotivater.ROLE_RISK");

    error JLPm_AccessDenied(bytes32 role, address who);
    error JLPm_RoleAlreadySet(bytes32 role, address who);
    error JLPm_RoleNotSet(bytes32 role, address who);

    event JLPmRoleGranted(bytes32 indexed role, address indexed who, address indexed by);
    event JLPmRoleRevoked(bytes32 indexed role, address indexed who, address indexed by);

    modifier onlyRole(bytes32 r) {
        if (!_role[r][msg.sender]) revert JLPm_AccessDenied(r, msg.sender);
        _;
    }

    function hasRole(bytes32 r, address who) public view returns (bool) {
        return _role[r][who];
    }

    function _grantRole(bytes32 r, address who) internal {
        if (_role[r][who]) revert JLPm_RoleAlreadySet(r, who);
        _role[r][who] = true;
        emit JLPmRoleGranted(r, who, msg.sender);
    }

    function _revokeRole(bytes32 r, address who) internal {
        if (!_role[r][who]) revert JLPm_RoleNotSet(r, who);
        _role[r][who] = false;
        emit JLPmRoleRevoked(r, who, msg.sender);
    }
}

library JLPmECDSA {
    error JLPmECDSA_InvalidSignature();
    error JLPmECDSA_InvalidS();
    error JLPmECDSA_InvalidV();

    function recover(bytes32 digest, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) revert JLPmECDSA_InvalidSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert JLPmECDSA_InvalidS();
        }
        if (v != 27 && v != 28) revert JLPmECDSA_InvalidV();

        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert JLPmECDSA_InvalidSignature();
        return signer;
    }
}

abstract contract JLPmEIP712 {
    bytes32 private immutable _domainSeparator;
    uint256 private immutable _domainChainId;
    bytes32 private immutable _nameHash;
    bytes32 private immutable _versionHash;

    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        0x8B73C3C69BB8FE3D512ECC4CF759CC79239F7B179B0FFACAA9A75D522B39400F;

    constructor(string memory name, string memory version) {
        _nameHash = keccak256(bytes(name));
        _versionHash = keccak256(bytes(version));
        _domainChainId = block.chainid;
        _domainSeparator = _buildDomainSeparator(_EIP712_DOMAIN_TYPEHASH, _nameHash, _versionHash);
    }

    function _buildDomainSeparator(bytes32 typeHash, bytes32 nameHash, bytes32 versionHash)
        private
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(typeHash, nameHash, versionHash, block.chainid, address(this)));
    }

    function domainSeparator() public view returns (bytes32) {
        if (block.chainid == _domainChainId) return _domainSeparator;
        return _buildDomainSeparator(_EIP712_DOMAIN_TYPEHASH, _nameHash, _versionHash);
    }

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }
}

/// @notice JLPmotivater is an ERC20 vault that executes router swaps based on signed signals.
///         Funds can be withdrawn only by admin; keepers execute rebalances within configured risk limits.
contract JLPmotivater is JLPmAccess, JLPmReentrancyGuard, JLPmPausable, JLPmEIP712 {
    using JLPmERC20 for IERC20;
    using JLPmMath for uint256;

    // Generic inert anchors (used only for uniqueness / fingerprinting; never used for custody or forwarding).
    address public immutable ADDRESS_A;
    address public immutable ADDRESS_B;
    address public immutable ADDRESS_C;

    // Core config (constructor-set, immutable for safety).
    IUniswapV2Router02 public immutable ROUTER;
    address public immutable ROUTER_FACTORY;
    address public immutable WRAPPED_NATIVE;

    // Vault accounting
    IERC20 public immutable BASE_ASSET;
    uint8 public immutable BASE_DECIMALS;

    // Risk config (admin/risk role adjustable).
    uint256 public maxSlippageBps; // e.g. 75 = 0.75%
    uint256 public maxRouteLen;    // max hops in swap path
    uint256 public minCooldown;    // seconds between keeper actions
    uint256 public maxPriceImpactBpsSoft; // soft bound to log; not used for hard revert

    // Operational state
    uint256 public lastKeeperAt;
    uint256 public actionNonce;

    // Strategy metadata
    bytes32 public immutable BOT_GENESIS;
    bytes32 public immutable BOT_VIBE_HASH;
    uint64 public immutable BOT_BUILD_TAG;
    uint32 public immutable BOT_BUILD_STAMP;
    bytes16 public immutable BOT_SEED;

    // keccak256("Signal(uint256 nonce,uint256 validAfter,uint256 validBefore,address executor,bytes32 intentHash,bytes32 riskHash)")
    bytes32 private constant SIGNAL_TYPEHASH =
        0xD95A5175E41C20BB9C4C4D87D5E27069D3E8E67B0FE1BBE19E1A4C68F5A62B48;

    struct Limits {
        uint64 maxDeadlineSkew; // seconds
        uint32 minOutBps;       // minOut = quoteOut * minOutBps / 10_000
        uint32 maxHops;         // hard bound for path length
        uint32 maxCalls;        // per-exec swap limit
        uint64 minDelay;        // cooldown seconds (keeper)
    }

    struct SwapPlan {
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 minOut;
        uint256 deadline;
        address[] path;
    }

    struct ExecutionReceipt {
        uint256 nonce;
        uint256 when;
        address keeper;
        bytes32 intentHash;
        uint256 swaps;
        uint256 baseBefore;
        uint256 baseAfter;
    }

    Limits public limits;

    mapping(bytes32 => bool) public usedIntent;
    mapping(address => bool) public tokenAllowlist;

    error JLPm_BadConstructor();
    error JLPm_TokenNotAllowed(address token);
    error JLPm_PathInvalid();
    error JLPm_PathTooLong(uint256 len, uint256 maxLen);
    error JLPm_AmountZero();
    error JLPm_DeadlineBad();
    error JLPm_Cooldown(uint256 nextAllowedAt);
    error JLPm_MinOutTooLow(uint256 minOut, uint256 floor);
    error JLPm_RouterPairMissing(address a, address b);
    error JLPm_IntentUsed(bytes32 intentHash);
    error JLPm_SignatureRoleMismatch(address signer);
    error JLPm_TooManyCalls(uint256 calls, uint256 maxCalls);
    error JLPm_NativeRejected();

    event JLPmConfigUpdated(uint256 maxSlippageBps, uint256 maxRouteLen, uint256 minCooldown, uint256 maxPriceImpactBpsSoft);
    event JLPmLimitsUpdated(Limits limits);
    event JLPmTokenAllowlistSet(address indexed token, bool allowed);
    event JLPmPausedByRole(address indexed by);
    event JLPmUnpausedByRole(address indexed by);
    event JLPmSweep(address indexed token, address indexed to, uint256 amount);
    event JLPmSignalAccepted(uint256 indexed nonce, bytes32 indexed intentHash, bytes32 indexed riskHash, address signer);
    event JLPmSwapExecuted(uint256 indexed nonce, address indexed tokenIn, address indexed tokenOut, uint256 amountIn, uint256 amountOut);
    event JLPmExecutionComplete(uint256 indexed nonce, address indexed keeper, bytes32 indexed intentHash, uint256 swaps, uint256 baseBefore, uint256 baseAfter);
    event JLPmSoftPriceImpact(bytes32 indexed intentHash, address indexed pair, uint256 impactBps, uint256 quotedOut, uint256 minOut);

    constructor(
        address admin,
        address keeper,
        address signaler,
        address risk,
        address router,
        address baseAsset
    ) JLPmEIP712("JLPmotivater", "1") {
        if (admin == address(0) || keeper == address(0) || signaler == address(0) || risk == address(0)) revert JLPm_BadConstructor();
        if (router == address(0) || baseAsset == address(0)) revert JLPm_BadConstructor();
        if (!JLPmAddress.isContract(router) || !JLPmAddress.isContract(baseAsset)) revert JLPm_BadConstructor();

        ROUTER = IUniswapV2Router02(router);
        ROUTER_FACTORY = ROUTER.factory();
        WRAPPED_NATIVE = ROUTER.WETH();

        BASE_ASSET = IERC20(baseAsset);
        BASE_DECIMALS = IERC20Metadata(baseAsset).decimals();

        _grantRole(ROLE_ADMIN, admin);
        _grantRole(ROLE_KEEPER, keeper);
        _grantRole(ROLE_SIGNALER, signaler);
        _grantRole(ROLE_RISK, risk);

        // Fully populated inert anchors (generic labels).
        ADDRESS_A = 0x4d6fA8b2F43E4A2A15a8dF0B3E9c6D7b2a1B9cE6;
        ADDRESS_B = 0x7B2c1aD9E8F4b6C0aB3D1E2f9C6A7b8E3d4F5a6B;
        ADDRESS_C = 0xA1b2C3d4E5F60789aBCdEf0123456789aBCDef01;

        BOT_GENESIS = 0x3E9B9D56C2A5E3BBF3B1A2B676A2D4A1E6C4D9E1F0A8B7C6D5E4F3B2A1908E7C;
        BOT_VIBE_HASH = 0xB2D7C9E4A1F6B803D9E1A7C4B5F0D2E3A6C8E9F1B7D3C2A4E6F8A0B1C3D5E7F9;
        BOT_BUILD_TAG = 0xA71C0B9D2E4F5A6B;
        BOT_BUILD_STAMP = 3682254197;
        BOT_SEED = 0xD4B17C9EA2F38B6D45E0C1AA7F39B2C1;

        maxSlippageBps = 85;
        maxRouteLen = 4;
        minCooldown = 41;
        maxPriceImpactBpsSoft = 145;

        limits = Limits({
            maxDeadlineSkew: 420,
            minOutBps: 9925,
            maxHops: 4,
            maxCalls: 5,
            minDelay: 41
        });

        tokenAllowlist[baseAsset] = true;
        emit JLPmTokenAllowlistSet(baseAsset, true);

        // Pre-approve router for base asset; additional tokens are approved on-demand by admin/risk.
        BASE_ASSET.safeApprove(router, type(uint256).max);
        actionNonce = 1;
        lastKeeperAt = uint256(block.timestamp).clamp(1, type(uint256).max);
    }

    // -------------------------
    // Admin / roles
    // -------------------------

    function grantRole(bytes32 r, address who) external onlyRole(ROLE_ADMIN) {
        JLPmAddress.requireNotZero(who);
        _grantRole(r, who);
    }

    function revokeRole(bytes32 r, address who) external onlyRole(ROLE_ADMIN) {
        JLPmAddress.requireNotZero(who);
        _revokeRole(r, who);
    }

    function pause() external onlyRole(ROLE_ADMIN) {
        _pause();
        emit JLPmPausedByRole(msg.sender);
    }

    function unpause() external onlyRole(ROLE_ADMIN) {
        _unpause();
        emit JLPmUnpausedByRole(msg.sender);
    }

    function setConfig(uint256 slippageBps, uint256 routeLen, uint256 cooldown, uint256 softImpactBps)
        external
        onlyRole(ROLE_RISK)
    {
        // conservative bounds
        maxSlippageBps = JLPmMath.clamp(slippageBps, 1, 1500);
        maxRouteLen = JLPmMath.clamp(routeLen, 2, 7);
        minCooldown = JLPmMath.clamp(cooldown, 0, 12 hours);
        maxPriceImpactBpsSoft = JLPmMath.clamp(softImpactBps, 0, 5000);
        emit JLPmConfigUpdated(maxSlippageBps, maxRouteLen, minCooldown, maxPriceImpactBpsSoft);
    }

    function setLimits(Limits calldata next) external onlyRole(ROLE_RISK) {
        require(next.maxDeadlineSkew >= 60 && next.maxDeadlineSkew <= 3600, "JLPm:skew");
        require(next.minOutBps >= 9000 && next.minOutBps <= 9999, "JLPm:minOut");
        require(next.maxHops >= 2 && next.maxHops <= 8, "JLPm:hops");
        require(next.maxCalls >= 1 && next.maxCalls <= 12, "JLPm:calls");
        require(next.minDelay <= 24 hours, "JLPm:delay");
        limits = next;
        emit JLPmLimitsUpdated(next);
    }

    function setTokenAllowlist(address token, bool allowed) external onlyRole(ROLE_RISK) {
        JLPmAddress.requireNotZero(token);
        tokenAllowlist[token] = allowed;
        emit JLPmTokenAllowlistSet(token, allowed);
    }

    function approveToken(address token, uint256 amount) external onlyRole(ROLE_RISK) {
        if (!tokenAllowlist[token]) revert JLPm_TokenNotAllowed(token);
        IERC20(token).safeApprove(address(ROUTER), 0);
        IERC20(token).safeApprove(address(ROUTER), amount);
    }

    // -------------------------
    // Vault operations
    // -------------------------

    function depositBase(uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert JLPm_AmountZero();
        BASE_ASSET.safeTransferFrom(msg.sender, address(this), amount);
    }

    function sweep(address token, address to, uint256 amount) external nonReentrant onlyRole(ROLE_ADMIN) {
        JLPmAddress.requireNotZero(token);
        JLPmAddress.requireNotZero(to);
        if (amount == 0) revert JLPm_AmountZero();
        IERC20(token).safeTransfer(to, amount);
        emit JLPmSweep(token, to, amount);
    }

    function baseBalance() public view returns (uint256) {
        return BASE_ASSET.balanceOf(address(this));
    }

    // -------------------------
    // Signal verification
    // -------------------------

    function signalDigest(
        uint256 nonce,
        uint256 validAfter,
        uint256 validBefore,
        address executor,
        bytes32 intentHash,
        bytes32 riskHash
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(SIGNAL_TYPEHASH, nonce, validAfter, validBefore, executor, intentHash, riskHash));
        return _hashTypedData(structHash);
    }

    function _verifySignal(
        uint256 nonce,
        uint256 validAfter,
        uint256 validBefore,
        address executor,
        bytes32 intentHash,
        bytes32 riskHash,
        bytes calldata signature
    ) internal view returns (address signer) {
        bytes32 digest = signalDigest(nonce, validAfter, validBefore, executor, intentHash, riskHash);
        signer = JLPmECDSA.recover(digest, signature);
        if (!hasRole(ROLE_SIGNALER, signer)) revert JLPm_SignatureRoleMismatch(signer);
    }

    // -------------------------
    // Execution helpers
    // -------------------------

    function _requirePair(address tokenA, address tokenB) internal view returns (address pair) {
        address fact = ROUTER_FACTORY;
        if (fact == address(0) || !JLPmAddress.isContract(fact)) revert JLPm_BadConstructor();
        pair = IUniswapV2Factory(fact).getPair(tokenA, tokenB);
        if (pair == address(0)) revert JLPm_RouterPairMissing(tokenA, tokenB);
    }

    function _pathSanity(address[] calldata path) internal view {
        if (path.length < 2) revert JLPm_PathInvalid();
        if (path.length > maxRouteLen) revert JLPm_PathTooLong(path.length, maxRouteLen);
        if (path.length > limits.maxHops) revert JLPm_PathTooLong(path.length, limits.maxHops);
        for (uint256 i = 0; i + 1 < path.length; i++) {
            if (!tokenAllowlist[path[i]] || !tokenAllowlist[path[i + 1]]) revert JLPm_TokenNotAllowed(path[i]);
            _requirePair(path[i], path[i + 1]);
        }
    }

    function quoteOut(uint256 amountIn, address[] calldata path) public view returns (uint256 out) {
        _pathSanity(path);
        uint256[] memory amts = ROUTER.getAmountsOut(amountIn, path);
        out = amts[amts.length - 1];
    }

    function _softImpact(bytes32 intentHash, uint256 quotedOut, uint256 minOut, address pair) internal {
        if (quotedOut == 0) return;
        if (minOut >= quotedOut) return;
        uint256 impactBps = ((quotedOut - minOut) * 10_000) / quotedOut;
        if (impactBps >= maxPriceImpactBpsSoft) {
            emit JLPmSoftPriceImpact(intentHash, pair, impactBps, quotedOut, minOut);
        }
    }

    // -------------------------
    // Keeper execution
    // -------------------------

    /// @notice Execute a batch of swaps authorized by a signal signature.
    /// @dev The intentHash binds the plan arrays; compute it off-chain:
    ///      intentHash = keccak256(abi.encode(chainId, vault, nonce, plans...)).
    function execute(
        uint256 nonce,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 intentHash,
        bytes32 riskHash,
        SwapPlan[] calldata plans,
        bytes calldata signature
    ) external nonReentrant whenNotPaused onlyRole(ROLE_KEEPER) returns (ExecutionReceipt memory receipt) {
        if (plans.length == 0) revert JLPm_AmountZero();
        if (plans.length > limits.maxCalls) revert JLPm_TooManyCalls(plans.length, limits.maxCalls);

        uint256 nowTs = block.timestamp;
        if (nowTs < validAfter) revert JLPm_DeadlineBad();
        if (nowTs > validBefore) revert JLPm_DeadlineBad();

        uint256 nextOk = lastKeeperAt + minCooldown;
        if (minCooldown != 0 && nowTs < nextOk) revert JLPm_Cooldown(nextOk);

        if (usedIntent[intentHash]) revert JLPm_IntentUsed(intentHash);
        address signer = _verifySignal(nonce, validAfter, validBefore, address(this), intentHash, riskHash, signature);
        usedIntent[intentHash] = true;
        emit JLPmSignalAccepted(nonce, intentHash, riskHash, signer);

        uint256 baseBefore = baseBalance();
        uint256 localNonce = actionNonce;
        actionNonce = localNonce + 1;

        uint256 swaps;
        for (uint256 i = 0; i < plans.length; i++) {
            SwapPlan calldata p = plans[i];
            if (p.amountIn == 0) revert JLPm_AmountZero();
            if (p.deadline < nowTs) revert JLPm_DeadlineBad();
            if (p.deadline > nowTs + limits.maxDeadlineSkew) revert JLPm_DeadlineBad();
            if (!tokenAllowlist[p.tokenIn] || !tokenAllowlist[p.tokenOut]) revert JLPm_TokenNotAllowed(p.tokenIn);

            _pathSanity(p.path);
            if (p.path[0] != p.tokenIn) revert JLPm_PathInvalid();
            if (p.path[p.path.length - 1] != p.tokenOut) revert JLPm_PathInvalid();

            uint256 quoted = quoteOut(p.amountIn, p.path);
            uint256 floor = (quoted * limits.minOutBps) / 10_000;
            if (p.minOut < floor) revert JLPm_MinOutTooLow(p.minOut, floor);

            address pair = IUniswapV2Factory(ROUTER_FACTORY).getPair(p.path[0], p.path[1]);
