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
