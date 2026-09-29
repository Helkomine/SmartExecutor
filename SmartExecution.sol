// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;
/// @author Helkomine (@Helkomine)

abstract contract SmartExecutorBase {
    bytes32 constant RDS_SENTINEL = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    // Tương đương với bytes32(erc7201("execution.active.slot")) trong Solidity
    bytes32 constant EXECUTION_ACTIVE_SLOT = 0xe174ed4e3d54110b9a3972ebecc852a49167f466185871b52a883f777e94cd00;
    // Tương đương với bytes32(erc7201("selfcall.allowed.slot")) trong Solidity
    bytes32 constant SELFCALL_ALLOWED_SLOT = 0x81624f1200d77dfa9dc68baa8d4456dfb417af96605ea2c49ed860decf4d2400;

    address immutable THIS_ADDRESS = address(this);

    modifier authenticateAccess() {
        bool executionActive;
        bool selfcallAllowed;
        assembly ("memory-safe") {
            executionActive := tload(EXECUTION_ACTIVE_SLOT)
            selfcallAllowed := tload(SELFCALL_ALLOWED_SLOT)
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
                tstore(SELFCALL_ALLOWED_SLOT, 0)
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
            for { let i } 1 {} {
                switch lt(i, bytecode.length)
                case 0 {
                    switch eq(i, bytecode.length)
                    case 0 {
                        revert(0, 0)
                    } default {
                        break
                    }
                }
                let command := shr(248, calldataload(i))
                switch lt(command, 4)
                case 1 {
                    switch lt(command, 2)
                    case 1 {
                        switch lt(command, 1)
                        // CALLDATACOPY
                        case 1 {
                            let destOff := calldataload(add(i, 1))
                            let siz := calldataload(add(i, 33))
                            if lt(destOff, 0x80) { revert(0, 0) }
                            calldatacopy(add(ptr, destOff), add(i, 65), siz)
                            i := add(i, add(siz, 65))
                        // RETURNDATACOPY
                        } default {
                            let destOff := calldataload(add(i, 1))
                            let off := calldataload(add(i, 33))
                            let siz := calldataload(add(i, 65))
                            if eq(siz, RDS_SENTINEL) { siz := returndatasize() }
                            if lt(destOff, 0x80) { revert(0, 0) }
                            returndatacopy(add(ptr, destOff), off, siz)
                            i := add(i, 97)
                        }
                    } default {
                        switch lt(command, 3)
                        // MCOPY
                        case 1 {
                            let destOff := calldataload(add(i, 1))
                            let off := calldataload(add(i, 33))
                            let siz := calldataload(add(i, 65))
                            if lt(destOff, 0x80) { revert(0, 0) }
                            if lt(off, 0x80) { revert(0, 0) }
                            mcopy(add(ptr, destOff), add(ptr, off), siz)
                            i := add(i, 97)
                        // JUMPI
                        } default {
                            let b := calldataload(add(i, 1))
                            let dest := calldataload(add(i, 33))
                            switch mload(add(ptr, b)) 
                            case 0 {
                                i := add(i, 65)
                            } default {
                                i := dest
                            }
                        }
                    }
                } default {
                    switch lt(command, 6)
                    case 1 {
                        switch lt(command, 5)
                        // CALL
                        case 1 {
                            let off := calldataload(add(i, 1))
                            if lt(off, 0x80) { revert(0, 0) }
                            let siz := calldataload(add(i, 33))
                            if eq(siz, RDS_SENTINEL) { siz := returndatasize() }
                            let reference := calldataload(add(i, 65))
                            if lt(reference, 0x80) { revert(0, 0) }
                            let pointer := add(ptr, reference)
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
                            if and(iszero(iszero(dismissRevert)), not(success)) {
                                returndatacopy(ptr, 0, returndatasize())
                                revert(0, returndatasize())
                            }
                            let dest := calldataload(add(i, 97))
                            if lt(dest, 0x80) { revert(0, 0) }
                            mstore(add(ptr, dest), success)
                            i := add(i, 129)
                        // SELFCALL
                        } default {
                            let off := calldataload(add(i, 1))
                            if lt(off, 0x80) { revert(0, 0) }
                            let siz := calldataload(add(i, 33))
                            if eq(siz, RDS_SENTINEL) { siz := returndatasize() }
                            let reference := calldataload(add(i, 65))
                            if lt(reference, 0x80) { revert(0, 0) }
                            let pointer := add(ptr, reference)
                            tstore(EXECUTION_ACTIVE_SLOT, 1)
                            let success := delegatecall(
                                mload(pointer), // gas
                                thisAddress, // target
                                add(ptr, off), // relative offset
                                siz,
                                0,
                                0
                            )
                            tstore(EXECUTION_ACTIVE_SLOT, 0)
                            let dismissRevert := mload(add(pointer, 0x20))
                            if and(iszero(iszero(dismissRevert)), not(success)) {
                                returndatacopy(ptr, 0, returndatasize())
                                revert(0, returndatasize())
                            }
                            let dest := calldataload(add(i, 97))
                            if lt(dest, 0x80) { revert(0, 0) }
                            mstore(add(ptr, dest), success)
                            i := add(i, 129)
                        }
                    } default {
                        switch lt(command, 7)
                        // STATICCALL
                        case 1 {
                            let off := calldataload(add(i, 1))
                            if lt(off, 0x80) { revert(0, 0) }
                            let siz := calldataload(add(i, 33))
                            if eq(siz, RDS_SENTINEL) { siz := returndatasize() }
                            let reference := calldataload(add(i, 65))
                            if lt(reference, 0x80) { revert(0, 0) }
                            let pointer := add(ptr, reference)
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
                            if and(iszero(iszero(dismissRevert)), not(success)) {
                                returndatacopy(ptr, 0, returndatasize())
                                revert(0, returndatasize())
                            }
                            let dest := calldataload(add(i, 97))
                            if lt(dest, 0x80) { revert(0, 0) }
                            mstore(add(ptr, dest), success)
                            i := add(i, 129)
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
