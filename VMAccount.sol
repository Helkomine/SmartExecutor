// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.30;
/// @author Helkomine (@Helkomine)

abstract contract SmartExecution {
    error AuthenticateFailed();

    address immutable THIS_ADDRESS = address(this);

    bool transient reentrant;
    bool transient selfcall;

    modifier authenticateAccess() {
        require(!reentrant || selfcall, AuthenticateFailed());
        selfcall = false;
        reentrant = true;
        _;
        reentrant = false;
    }

    fallback() external payable authenticateAccess {
        address thisAddress = THIS_ADDRESS;
        assembly ("memory-safe") {
            if calldatasize() {
                let ptr := mload(0x40)
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
                                calldatacopy(add(ptr, destOff), add(i, 65), siz)
                                i := add(i, add(siz, 65))
                            // RETURNDATACOPY
                            } default {
                                let destOff := calldataload(add(i, 1))
                                let off := calldataload(add(i, 33))
                                let siz := calldataload(add(i, 65))
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
                                mcopy(add(ptr, destOff), off, siz)
                                i := add(i, 97)
                            // JUMPI
                            } default {
                                let dest := calldataload(add(i, 1))
                                let b := calldataload(add(i, 33))
                                switch b 
                                case 1 {
                                    i := dest
                                } default {
                                    i := add(i, 65)
                                }
                            }
                        }
                    } default {
                        switch lt(command, 6)
                        case 1 {
                            switch lt(command, 5)
                            // CALL
                            case 1 {
                                let reference := calldataload(add(i, 1))
                                let pointer := add(ptr, reference)
                                let g := mload(pointer)
                                let target := mload(add(pointer, 0x20))
                                let value := mload(add(pointer, 0x40))
                                let off := mload(add(pointer, 0x60))
                                let siz := mload(add(pointer, 0x80))
                                let dismissRevert := mload(add(pointer, 0xa0))
                                let dest := mload(add(pointer, 0xc0))
                                let success := call(g, target, value, add(ptr, off), siz, 0, 0)
                                switch dismissRevert
                                case 0 {
                                    returndatacopy(ptr, 0, returndatasize())
                                    revert(0, returndatasize())
                                } 
                                i := add(i, 33)
                            // SELFCALL
                            } default {
                                let reference := calldataload(add(i, 1))
                                let pointer := add(ptr, reference)
                                let g := mload(pointer)
                                let off := mload(add(pointer, 0x20))
                                let siz := mload(add(pointer, 0x40))
                                let dismissRevert := mload(add(pointer, 0x60))
                                let dest := mload(add(pointer, 0x80))
                                tstore(reentrant.slot, 1)
                                let success := delegatecall(g, thisAddress, off, siz, 0, 0)
                                switch dismissRevert
                                case 0 {
                                    returndatacopy(ptr, 0, returndatasize())
                                    revert(0, returndatasize())
                                }
                                mstore(dest, success)
                                i := add(i, 33)
                            }
                        } default {
                            switch lt(command, 7)
                            // STATICCALL
                            case 1 {
                                let reference := calldataload(add(i, 1))
                                let pointer := add(ptr, reference)
                                let g := mload(pointer)
                                let target := mload(add(pointer, 0x20))
                                let off := mload(add(pointer, 0x40))
                                let siz := mload(add(pointer, 0x60))
                                let dismissRevert := mload(add(pointer, 0x80))
                                let dest := mload(add(pointer, 0xa0))
                                let success := staticcall(g, target, off, siz, 0, 0)
                                switch dismissRevert
                                case 0 {
                                    returndatacopy(ptr, 0, returndatasize())
                                    revert(0, returndatasize())
                                }
                                mstore(dest, success)
                                i := add(i, 33)
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
}
