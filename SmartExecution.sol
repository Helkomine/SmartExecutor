// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;
/// @author Helkomine (@Helkomine)

contract SmartExecutor {
    bytes32 constant RETURNDATASIZE_SETINEL = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    address immutable THIS_ADDRESS = address(this);

    bool transient executionActive;
    // Biến đệm được thêm vào để ngăn compiler pack hai biến bool thành một slot, điều này dẫn đến ghi đè khi thao tác TSTORE tại slot được chỉ định trong khối mã assembly
    bytes32 private transient _gap;
    bool transient selfcallAllowed;

    modifier authenticateAccess() {
        if (!executionActive) {
            executionActive = true;
            _;
            executionActive = false;
        } else if (selfcallAllowed) {
            selfcallAllowed = false;
            _;
        }
    }

    fallback() external payable authenticateAccess {
        address thisAddress = THIS_ADDRESS;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, caller())
            mstore(add(ptr, 0x20), callvalue())
            mstore(add(ptr, 0x40), calldatasize())
            for { let i } 1 {} {
                switch lt(i, calldatasize())
                case 0 {
                    switch eq(i, calldatasize())
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
                            let siz
                            switch eq(siz, RETURNDATASIZE_SETINEL)
                            case 1 {
                                siz := returndatasize()
                            } default {
                                siz := calldataload(add(i, 65))
                            }
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
                            let siz
                            switch eq(siz, RETURNDATASIZE_SETINEL)
                            case 1 {
                                siz := returndatasize()
                            } default {
                                siz := calldataload(add(i, 65))
                            }
                            if lt(destOff, 0x80) { revert(0, 0) }
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
                            let pointer
                            {
                                let reference := calldataload(add(i, 97))
                                if lt(reference, 0x80) { revert(0, 0) }
                                pointer := add(ptr, reference)
                            }
                            let success
                            {
                                let g := mload(pointer)
                                let target := mload(add(pointer, 0x20))
                                let value := mload(add(pointer, 0x40))
                                let off := calldataload(add(i, 1))
                                let instance := add(ptr, off)
                                let siz
                                switch eq(siz, RETURNDATASIZE_SETINEL)
                                case 1 {
                                    siz := returndatasize()
                                } default {
                                    siz := calldataload(add(i, 33))
                                }
                                success := call(g, target, value, instance, siz, 0, 0)
                                mstore(add(ptr, 0x60), returndatasize())
                            }
                            let dismissRevert := mload(add(pointer, 0x60))
                            switch dismissRevert
                            case 0 {
                                if not(success) {
                                    returndatacopy(ptr, 0, returndatasize())
                                    revert(0, returndatasize())
                                }
                            }
                            let dest := calldataload(add(i, 65))
                            if lt(dest, 0x80) { revert(0, 0) }
                            mstore(add(ptr, dest), success)
                            i := add(i, 129)
                        // SELFCALL
                        } default {
                            let pointer
                            {
                                let reference := calldataload(add(i, 97))
                                if lt(reference, 0x80) { revert(0, 0) }
                                pointer := add(ptr, reference)
                            }
                            let success
                            {
                                let g := mload(pointer)
                                let off := calldataload(add(i, 1))
                                let siz := calldataload(add(i, 33))
                                tstore(selfcallAllowed.slot, 1)
                                success := delegatecall(g, thisAddress, add(ptr, off), siz, 0, 0)
                            }
                            let dismissRevert := mload(add(pointer, 0x20))
                            switch dismissRevert
                            case 0 {
                                if not(success) {
                                    returndatacopy(ptr, 0, returndatasize())
                                    revert(0, returndatasize())
                                }
                            }
                            let dest := calldataload(add(i, 65))
                            if lt(dest, 0x80) { revert(0, 0) }
                            mstore(add(ptr, dest), success)
                            i := add(i, 129)
                        }
                    } default {
                        switch lt(command, 7)
                        // STATICCALL
                        case 1 {
                            let pointer
                            {
                                let reference := calldataload(add(i, 97))
                                if lt(reference, 0x80) { revert(0, 0) }
                                pointer := add(ptr, reference)
                            }
                            let success
                            {
                                let g := mload(pointer)
                                let target := mload(add(pointer, 0x20))
                                let off := calldataload(add(i, 1))
                                let siz := calldataload(add(i, 33))
                                success := staticcall(g, target, add(ptr, off), siz, 0, 0)
                                mstore(add(ptr, 0x60), returndatasize())
                            }
                            let dismissRevert := mload(add(pointer, 0x40))
                            switch dismissRevert
                            case 0 {
                                if not(success) {
                                    returndatacopy(ptr, 0, returndatasize())
                                    revert(0, returndatasize())
                                }
                            }
                            let dest := calldataload(add(i, 65))
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
