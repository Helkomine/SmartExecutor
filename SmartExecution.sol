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
                            if gt(end, lastOffset) { revert(0, 0) }
                            let destOffset := calldataload(add(i, 1))
                            if lt(destOffset, 0x80) { revert(0, 0) }
                            let size := calldataload(add(i, 33))
                            end := add(end, size)
                            if gt(i, end) { revert(0, 0) } // overflow
                            if gt(end, lastOffset) { revert(0, 0) }
                            calldatacopy(add(ptr, destOffset), add(i, 65), size)
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
                            let pos := add(ptr, destOffset)
                            if gt(destOffset, pos) { revert(0, 0) } // overflow
                            returndatacopy(pos, offset, size)
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
                            let siz := calldataload(add(i, 65))
                            if lt(destOffset, 0x80) { revert(0, 0) }
                            let pos := add(ptr, destOffset)
                            if gt(destOffset, pos) { revert(0, 0) } // overflow
                            mcopy(pos, add(ptr, offset), siz)
                            i := end
                        // JUMPI
                        } default {
                            let end := add(i, 65)
                            if gt(i, end) { revert(0, 0) } // overflow
                            let b := calldataload(add(i, 1))
                            if lt(b, 0x80) { revert(0, 0) }
                            let jumpPc := calldataload(add(i, 33))
                            if and(lt(jumpPc, bytecode.offset), gt(jumpPc, lastOffset)) { revert(0, 0) }
                            let bOffset := add(ptr, b)
                            if gt(b, bOffset) { revert(0, 0) } // overflow
                            switch mload(bOffset) 
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
                            let newPc := add(i, 129)
                            if gt(newPc, lastOffset) { revert(0, 0) }
                            let off := calldataload(add(i, 1))
                            if lt(off, 0x80) { revert(0, 0) }
                            let siz := calldataload(add(i, 33))
                            if eq(siz, RDS_SENTINEL) { siz := returndatasize() }
                            let pointer
                            {
                                let reference := calldataload(add(i, 65))
                                if lt(reference, 0x80) { revert(0, 0) }
                                pointer := add(ptr, reference)
                            }
                            let success := call(
                                mload(pointer), // gas
                                mload(add(pointer, 0x20)), // target
                                mload(add(pointer, 0x40)), // value
                                add(ptr, off), // relative offset
                                siz,
                                0,
                                0
                            )
                            mstore(add(ptr, 0x60), returndatasize())
                            let dismissRevert := mload(add(pointer, 0x60))
                            if and(iszero(iszero(dismissRevert)), iszero(success)) {
                                returndatacopy(ptr, 0, returndatasize())
                                revert(0, returndatasize())
                            }
                            let dest := calldataload(add(i, 97))
                            if lt(dest, 0x80) { revert(0, 0) }
                            mstore(add(ptr, dest), success)
                            i := newPc
                        // SELFCALL
                        } default {
                            let end := add(i, 129)
                            if gt(end, lastOffset) { revert(0, 0) }
                            let off := calldataload(add(i, 1))
                            if lt(off, 0x80) { revert(0, 0) }
                            let siz := calldataload(add(i, 33))
                            if eq(siz, RDS_SENTINEL) { siz := returndatasize() }
                            let pointer
                            {
                                let reference := calldataload(add(i, 65))
                                if lt(reference, 0x80) { revert(0, 0) }
                                pointer := add(ptr, reference)
                            }
                            tstore(SELFCALL_ENTRY_SLOT, 1)
                            let success := delegatecall(
                                mload(pointer), // gas
                                thisAddress, // target
                                add(ptr, off), // relative offset
                                siz,
                                0,
                                0
                            )
                            tstore(SELFCALL_ENTRY_SLOT, 0)
                            let dismissRevert := mload(add(pointer, 0x20))
                            if and(iszero(iszero(dismissRevert)), iszero(success)) {
                                returndatacopy(ptr, 0, returndatasize())
                                revert(0, returndatasize())
                            }
                            let dest := calldataload(add(i, 97))
                            if lt(dest, 0x80) { revert(0, 0) }
                            mstore(add(ptr, dest), success)
                            i := end
                        }
                    } default {
                        switch lt(command, 7)
                        // STATICCALL
                        case 1 {
                            let end := add(i, 129)
                            if gt(end, lastOffset) { revert(0, 0) }
                            let off := calldataload(add(i, 1))
                            if lt(off, 0x80) { revert(0, 0) }
                            let siz := calldataload(add(i, 33))
                            if eq(siz, RDS_SENTINEL) { siz := returndatasize() }
                            let pointer
                            {
                                let reference := calldataload(add(i, 65))
                                if lt(reference, 0x80) { revert(0, 0) }
                                pointer := add(ptr, reference)
                            }
                            let success := staticcall(
                                mload(pointer),
                                mload(add(pointer, 0x20)),
                                add(ptr, off),
                                siz,
                                0,
                                0
                            )
                            mstore(add(ptr, 0x60), returndatasize())
                            let dismissRevert := mload(add(pointer, 0x40))
                            if and(iszero(iszero(dismissRevert)), iszero(success)) {
                                returndatacopy(ptr, 0, returndatasize())
                                revert(0, returndatasize())
                            }
                            let dest := calldataload(add(i, 97))
                            if lt(dest, 0x80) { revert(0, 0) }
                            mstore(add(ptr, dest), success)
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
