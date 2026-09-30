// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;
/// @author Helkomine (@Helkomine)

abstract contract SmartExecutorBase {
    bytes32 constant RDS_SENTINEL = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    // Tương đương với bytes32(erc7201("execution.active.slot")) trong Solidity
    bytes32 constant EXECUTION_ACTIVE_SLOT = 0xe174ed4e3d54110b9a3972ebecc852a49167f466185871b52a883f777e94cd00;
    // Tương đương với bytes32(erc7201("selfcall.entry.slot")) trong Solidity
    bytes32 constant SELFCALL_ENTRY_SLOT = 0x59b4a219f862d0a711b522abd2b90521e73f46ac75eba37012a47fdd90433200;

    address immutable THIS_ADDRESS = address(this);

    modifier authenticateAccess() {
        bool executionActive;
        bool selfcallAllowed;
        assembly ("memory-safe") {
            executionActive := tload(EXECUTION_ACTIVE_SLOT)
            selfcallAllowed := tload(SELFCALL_ENTRY_SLOT)
        }
        if (!executionActive) {
            assembly ("memory-safe") {
                tstore(EXECUTION_ACTIVE_SLOT, 1)
            }
            _;
            assembly ("memory-safe") {
                tstore(EXECUTION_ACTIVE_SLOT, 0)
            }
        } else if (selfcallAllowed) {
            assembly ("memory-safe") {
                tstore(SELFCALL_ENTRY_SLOT, 0)
            }
            _;
        }
    }

    function _executeCode(bytes calldata bytecode) internal authenticateAccess {
        address thisAddress = THIS_ADDRESS;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, caller())
            mstore(add(ptr, 0x20), callvalue())
            mstore(add(ptr, 0x40), calldatasize())
            mstore(add(ptr, 0x60), 0) // đảm bảo vùng nhớ được dùng đã được làm sạch
            let lastOffset := add(bytecode.offset, bytecode.length)
            if gt(bytecode.offset, lastOffset) { revert(0, 0) } // overflow
            for { let i := bytecode.offset } lt(i, lastOffset) {} {
                let command := shr(248, calldataload(i))
                switch lt(command, 4)
                case 1 {
                    switch lt(command, 2)
                    case 1 {
                        switch lt(command, 1)
                        // CALLDATACOPY
                        case 1 {
                            let end := add(i, 65)
                            if gt(i, end) { revert(0, 0) } // overflow
                            let destOffset := calldataload(add(i, 1))
                            let size := calldataload(add(i, 33))
                            if lt(destOffset, 0x80) { revert(0, 0) }
                            end := add(end, size)
                            if gt(size, end) { revert(0, 0) } // overflow
                            if gt(end, lastOffset) { revert(0, 0) }
                            destOffset := add(ptr, destOffset)
                            if gt(ptr, destOffset) { revert(0, 0) } // overflow
                            if gt(size, add(size, destOffset)) { revert(0, 0) } // kiểm tra trần bộ nhớ bằng overflow
                            calldatacopy(destOffset, add(i, 65), size)
                            i := end
                        // RETURNDATACOPY
                        } default {
                            let end := add(i, 97)
                            if gt(i, end) { revert(0, 0) } // overflow
                            if gt(end, lastOffset) { revert(0, 0) }
                            let destOffset := calldataload(add(i, 1))
                            let offset := calldataload(add(i, 33))
                            let size := calldataload(add(i, 65))
                            if eq(size, RDS_SENTINEL) { size := returndatasize() }
                            if lt(destOffset, 0x80) { revert(0, 0) }
                            destOffset := add(ptr, destOffset)
                            if gt(ptr, destOffset) { revert(0, 0) } // overflow
                            if gt(size, add(size, destOffset)) { revert(0, 0) } // kiểm tra trần bộ nhớ bằng overflow
                            if gt(size, add(size, offset)) { revert(0, 0) } // kiểm tra trần return data buffer bằng overflow
                            returndatacopy(destOffset, offset, size)
                            i := end
                        }
                    } default {
                        switch lt(command, 3)
                        // MCOPY
                        case 1 {
                            let end := add(i, 97)
                            if gt(i, end) { revert(0, 0) } // overflow
                            if gt(end, lastOffset) { revert(0, 0) }
                            let destOffset := calldataload(add(i, 1))
                            let offset := calldataload(add(i, 33))
                            let size := calldataload(add(i, 65))
                            if lt(destOffset, 0x80) { revert(0, 0) }
                            destOffset := add(ptr, destOffset)
                            if gt(ptr, destOffset) { revert(0, 0) } // overflow
                            offset := add(ptr, offset)
                            if gt(ptr, offset) { revert(0, 0) } // overflow
                            if gt(size, add(size, destOffset)) { revert(0, 0) } // kiểm tra trần bộ nhớ bằng overflow
                            if gt(size, add(size, offset)) { revert(0, 0) } // kiểm tra trần bộ nhớ bằng overflow
                            mcopy(destOffset, offset, size)
                            i := end
                        // JUMPI
                        } default {
                            let end := add(i, 65)
                            if gt(i, end) { revert(0, 0) } // overflow
                            if gt(end, lastOffset) { revert(0, 0) }
                            let b := calldataload(add(i, 1))
                            let jumpPc := calldataload(add(i, 33))
                            if lt(b, 0x80) { revert(0, 0) }
                            jumpPc := add(bytecode.offset, jumpPc)
                            if gt(bytecode.offset, jumpPc) { revert(0, 0) } // overflow
                            if gt(jumpPc, lastOffset) { revert(0, 0) }
                            b := add(ptr, b)
                            if gt(ptr, b) { revert(0, 0) } // overflow
                            if gt(b, add(b, 0x1f)) { revert(0, 0) } // kiểm tra trần bộ nhớ bằng overflow
                            switch mload(b) 
                            case 0 {
                                i := end
                            } default {
                                i := jumpPc
                            }
                        }
                    }
                } default {
                    switch lt(command, 6)
                    case 1 {
                        switch lt(command, 5)
                        // CALL
                        case 1 {
                            let end := add(i, 129)
                            if gt(i, end) { revert(0, 0) } // overflow
                            if gt(end, lastOffset) { revert(0, 0) }
                            let offset := calldataload(add(i, 1))
                            let size := calldataload(add(i, 33))
                            let reference := calldataload(add(i, 65))
                            if lt(offset, 0x80) { revert(0, 0) }
                            if eq(size, RDS_SENTINEL) { size := returndatasize() }
                            if lt(reference, 0x80) { revert(0, 0) }
                            reference := add(ptr, reference)
                            if gt(ptr, reference) { revert(0, 0) } // overflow
                            if gt(reference, add(reference, 0x7f)) { revert(0, 0) } // kiểm tra trần bộ nhớ bằng overflow
                            offset := add(ptr, offset)
                            if gt(ptr, offset) { revert(0, 0) } // overflow
                            if gt(size, add(size, offset)) { revert(0, 0) } // kiểm tra trần bộ nhớ bằng overflow
                            let success := call(
                                mload(reference), // gas
                                mload(add(reference, 0x20)), // target
                                mload(add(reference, 0x40)), // value
                                offset, // relative offset
                                size,
                                0,
                                0
                            )
                            mstore(add(ptr, 0x60), returndatasize())
                            let dismissRevert := mload(add(reference, 0x60))
                            if and(iszero(iszero(dismissRevert)), iszero(success)) {
                                returndatacopy(ptr, 0, returndatasize())
                                revert(0, returndatasize())
                            }
                            let dest := calldataload(add(i, 97))
                            if lt(dest, 0x80) { revert(0, 0) }
                            dest := add(ptr, dest)
                            if gt(ptr, dest) { revert(0, 0) } // overflow
                            if gt(dest, add(dest, 0x1f)) { revert(0, 0) } // kiểm tra trần bộ nhớ bằng overflow
                            mstore(dest, success)
                            i := end
                        // SELFCALL
                        } default {
                            let end := add(i, 129)
                            if gt(i, end) { revert(0, 0) } // overflow
                            if gt(end, lastOffset) { revert(0, 0) }
                            let offset := calldataload(add(i, 1))
                            let size := calldataload(add(i, 33))
                            let reference := calldataload(add(i, 65))
                            if lt(offset, 0x80) { revert(0, 0) }
                            if eq(size, RDS_SENTINEL) { size := returndatasize() }
                            if lt(reference, 0x80) { revert(0, 0) }
                            reference := add(ptr, reference)
                            if gt(ptr, reference) { revert(0, 0) } // overflow
                            if gt(reference, add(reference, 0x3f)) { revert(0, 0) } // kiểm tra trần bộ nhớ bằng overflow
                            tstore(SELFCALL_ENTRY_SLOT, 1)
                            offset := add(ptr, offset)
                            if gt(ptr, offset) { revert(0, 0) } // overflow
                            if gt(size, add(size, offset)) { revert(0, 0) } // kiểm tra trần bộ nhớ bằng overflow
                            let success := delegatecall(
                                mload(reference), // gas
                                thisAddress, // target
                                offset, // relative offset
                                size,
                                0,
                                0
                            )
                            mstore(add(ptr, 0x60), returndatasize())
                            tstore(SELFCALL_ENTRY_SLOT, 0)
                            let dismissRevert := mload(add(reference, 0x20))
                            if and(iszero(iszero(dismissRevert)), iszero(success)) {
                                returndatacopy(ptr, 0, returndatasize())
                                revert(0, returndatasize())
                            }
                            let dest := calldataload(add(i, 97))
                            if lt(dest, 0x80) { revert(0, 0) }
                            dest := add(ptr, dest)
                            if gt(ptr, dest) { revert(0, 0) } // overflow
                            if gt(dest, add(dest, 0x1f)) { revert(0, 0) } // kiểm tra trần bộ nhớ bằng overflow
                            mstore(dest, success)
                            i := end
                        }
                    } default {
                        switch lt(command, 7)
                        // STATICCALL
                        case 1 {
                            let end := add(i, 129)
                            if gt(i, end) { revert(0, 0) } // overflow
                            if gt(end, lastOffset) { revert(0, 0) }
                            let offset := calldataload(add(i, 1))
                            let size := calldataload(add(i, 33))
                            let reference := calldataload(add(i, 65))
                            if lt(offset, 0x80) { revert(0, 0) }
                            if eq(size, RDS_SENTINEL) { size := returndatasize() }
                            if lt(reference, 0x80) { revert(0, 0) }
                            reference := add(ptr, reference)
                            if gt(ptr, reference) { revert(0, 0) } // overflow
                            if gt(reference, add(reference, 0x5f)) { revert(0, 0) } // kiểm tra trần bộ nhớ bằng overflow
                            offset := add(ptr, offset)
                            if gt(ptr, offset) { revert(0, 0) } // overflow
                            if gt(size, add(size, offset)) { revert(0, 0) } // kiểm tra trần bộ nhớ bằng overflow
                            let success := staticcall(
                                mload(reference),
                                mload(add(reference, 0x20)),
                                offset,
                                size,
                                0,
                                0
                            )
                            mstore(add(ptr, 0x60), returndatasize())
                            let dismissRevert := mload(add(reference, 0x40))
                            if and(iszero(iszero(dismissRevert)), iszero(success)) {
                                returndatacopy(ptr, 0, returndatasize())
                                revert(0, returndatasize())
                            }
                            let dest := calldataload(add(i, 97))
                            if lt(dest, 0x80) { revert(0, 0) }
                            dest := add(ptr, dest)
                            if gt(ptr, dest) { revert(0, 0) } // overflow
                            if gt(dest, add(dest, 0x1f)) { revert(0, 0) } // kiểm tra trần bộ nhớ bằng overflow
                            mstore(dest, success)
                            i := end
                        // fallback
                        } default {
                            revert(0, 0)
                        }
                    }
                }
            }
        }
    }
}

contract SmartExecutor is SmartExecutorBase {
    fallback() external payable {
        _executeCode(msg.data);
    }
}
