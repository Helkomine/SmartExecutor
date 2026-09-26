// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.35;
/// @author Helkomine (@Helkomine)

library BytesTransient {
    /**
     * @dev Reverts when transient-storage slot arithmetic overflows.
     *
     * This error protects the cache implementation and is not part of the
     * Solver protocol semantics.
     */
    error Overflow();

    /**
     * @dev Reverts when a cached `bytes` value exceeds
     *      `MAX_TOTAL_LENGTH`.
     *
     * @param totalLength The length that exceeded the implementation limit.
     */
    error TotalLengthTooLarge(uint256 totalLength);

    /**
     * @dev Maximum number of bytes that a cache entry can contain.
     *
     * This limit protects the transient-storage cache implementation and is
     * not part of the Solver protocol semantics.
     */
    uint64 constant MAX_TOTAL_LENGTH = type(uint64).max;

    /**
     * @dev Loads a cached `bytes` value from transient storage into memory.
     *
     * The value is expected to be stored as a length word followed by its data
     * words. If the length is not a multiple of 32 bytes, only the bytes within
     * the logical length are copied into memory; unused bytes in the final word
     * are ignored.
     *
     * Reverts with `TotalLengthTooLarge` if the cached length exceeds
     * `MAX_TOTAL_LENGTH`, or with `Overflow` if the transient storage slot
     * arithmetic overflows.
     *
     * @param namespace The transient storage namespace containing the cached value.
     * @return data The cached bytes value reconstructed in memory.
     */
    function _getCacheData(bytes32 namespace) 
        internal 
        view 
        returns (bytes memory data) 
    {
        bytes4 lengthTooLargeSelector = TotalLengthTooLarge.selector;
        bytes4 overflowSelector = Overflow.selector;
        uint64 maxTotalLength = MAX_TOTAL_LENGTH;
        assembly ("memory-safe") {
            data := mload(64)
            let length := tload(namespace)
            if gt(length, maxTotalLength) {
                mstore(0, lengthTooLargeSelector)
                mstore(4, length)
                revert(0, 36)
            }
            mstore(data, length)
            let offset := add(data, 32)
            if length {
                let floorTotalSlot := shr(5, length)
                let totalSlot := shr(5, add(length, 31))
                let lastSlot := add(namespace, floorTotalSlot)
                {
                    let _namespace := add(namespace, 1)
                    if gt(namespace, _namespace) {
                        mstore(0, overflowSelector)
                        revert(0, 4)
                    }
                    namespace := _namespace
                    if gt(namespace, lastSlot) {
                        mstore(0, overflowSelector)
                        revert(0, 4)
                    }
                }
                for { let i } lt(i, floorTotalSlot) { i := add(i, 1) } {
                    mstore(add(offset, shl(5, i)), tload(add(namespace, i)))
                }
                let roundingLength := shl(5, floorTotalSlot)
                let bytesLeft := sub(length, roundingLength)
                if bytesLeft {
                    let bitsLeft := shl(3, bytesLeft)
                    let bitPadding := sub(256, bitsLeft)
                    let rawWord := tload(lastSlot)
                    let mask := shl(bitPadding, shr(bitPadding, rawWord))
                    mstore(add(offset, roundingLength), mask)
                }
                offset := add(offset, shl(5, totalSlot))
            }
            mstore(64, offset)
        }
    }
}

abstract contract VMAccountBase {
    using BytesTransient for bytes32;

    error InvalidEntry(bytes data);
    error InvalidCommitment(bytes32 commitment);
    error SelfCallFailed(bytes reason);

    bytes32 constant CODE_SLOT = bytes32(erc7201("code.slot"));

    address immutable THIS_ADDRESS = address(this);

    // slot 0
    address transient caller;
    // slot 1
    uint256 transient callvalue;
    // slot 2
    uint256 transient calldatasize;
    // slot 3
    uint256 transient returndatasize;

    uint16 transient depth;
    uint24 transient continuation;
    bool transient isSelfcall;
    bool transient selfcallEntry;
    bool transient useCalldataAsCode;
    uint256 transient offset;
    uint256 transient length;
    bytes32 transient snapshotCommitment;

    function _entryAccount(bytes calldata data) internal {
        unchecked {
            depth++;
            continuation++;
        }
        if (depth == 1) {
            require(_validateEntry(data), InvalidEntry(data));
        } else {
            if (selfcallEntry) {
                selfcallEntry = false;
                _executeCode(msg.data);
            } else {
                bytes calldata slice = _validateCommitment();
                if (isSelfcall) {
                    isSelfcall = false;
                    selfcallEntry = true;
                    (bool success, bytes memory result) = THIS_ADDRESS.call(abi.encodePacked(
                        CODE_SLOT._getCacheData(),
                        slice
                    ));
                    require(success, SelfCallFailed(result));
                } else {
                    _executeCode(slice);
                }
            }
        }
        if (depth == 1) continuation = 0;
        unchecked { depth--; }
    }

    function _validateEntry(bytes calldata data) internal virtual returns (bool);

    function _executeCode(bytes calldata code) internal virtual;

    function _validateCommitment() internal returns (bytes calldata slice) {
        slice = msg.data[offset : offset + length];
        if (useCalldataAsCode) {
            bytes32 commitment = keccak256(abi.encodePacked(
                abi.encode(msg.sender),
                abi.encode(depth),
                abi.encode(continuation),
                keccak256(slice)
            ));
            require(snapshotCommitment == commitment, InvalidCommitment(commitment));
            offset = 0;
            length = 0;
            useCalldataAsCode = false;
        } else {
            assembly ("memory-safe") {
                slice.length := 0
            }
        }
    }
}

abstract contract VMAccount is VMAccountBase {
    uint256 constant CALLDATACOPY = 0x00;
    uint256 constant CALLDATALOAD = 0x01;
    uint256 constant RETURNDATACOPY = 0x02;
    uint256 constant TLOAD = 0x03;
    uint256 constant TSTORE = 0x04;
    uint256 constant JUMPI = 0x05;
    uint256 constant CALL = 0x06;
    uint256 constant STATICCALL = 0x07;
 
    function _executeCode(bytes calldata code) internal virtual override {
        if (code.length > 0) {
            caller = msg.sender;
            callvalue = msg.value;
            calldatasize = msg.data.length;
            assembly ("memory-safe") {
                let ptr := mload(0x40)
                for { let i } 1 {} {
                    let command := shr(248, calldataload(add(code.offset, i)))
                    switch lt(i, code.length)
                    case 0 {
                        switch eq(i, code.length)
                        case 0 {
                            revert(0, 0)
                        } default {
                            break
                        }
                    }
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
                            // CALLDATALOAD
                            } default {
                                let off := calldataload(add(i, 1))
                                let dest := calldataload(add(i, 33))
                                mstore(add(ptr, dest), calldataload(off))
                                i := add(i, 65)
                            }
                        } default {
                            switch lt(command, 3)
                            // RETURNDATACOPY
                            case 1 {
                                let destOff := calldataload(add(i, 1))
                                let off := calldataload(add(i, 33))
                                let siz := calldataload(add(i, 65))
                                returndatacopy(add(ptr, destOff), off, siz)
                                i := add(i, 97)
                            // TLOAD
                            } default {
                                let key := calldataload(add(i, 1))
                                let dest := calldataload(add(i, 33))
                                mstore(add(ptr, dest), tload(key))
                                i := add(i, 65)
                            }
                        }
                    } default {
                        switch lt(command, 6)
                        case 1 {
                            switch lt(command, 5)
                            // TSTORE
                            case 1 {
                                let key := calldataload(add(i, 1))
                                let value := calldataload(add(i, 33))
                                if lt(key, 256) { revert(0, 0) }
                                tstore(key, value)
                                i := add(i, 65)
                            // JUMPI
                            } default {
                                let dest := calldataload(add(i, 1))
                                let b := calldataload(add(i, 33))
                                if b { i := dest }
                            }
                        } default {
                            switch lt(command, 7)
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
                                let calldataAsCode := mload(add(pointer, 0xe0))
                                let whitelister := mload(add(pointer, 0x100))
                                let sliceOffset := mload(add(pointer, 0x120))
                                let sliceSize := mload(add(pointer, 0x140))
                                let startOffset := mload(add(pointer, 0x160))
                                if calldataAsCode {
                                    tstore(useCalldataAsCode.slot, calldataAsCode)
                                    tstore(offset.slot, sliceOffset)
                                    tstore(length.slot, sliceSize)
                                    let blobHash := keccak256(add(ptr, startOffset), sliceSize)
                                    mstore(ptr, whitelister)
                                    mstore(add(ptr, 0x20), tload(depth.slot))
                                    mstore(add(ptr, 0x40), tload(continuation.slot))
                                    mstore(add(ptr, 0x60), blobHash)
                                    let commitment := keccak256(0, 0x80)
                                    tstore(snapshotCommitment.slot, commitment)
                                }
                                let success := call(g, target, value, add(ptr, off), siz, 0, 0)
                                switch dismissRevert
                                case 0 {
                                    returndatacopy(ptr, 0, returndatasize())
                                    revert(0, returndatasize())
                                } 
                                i := add(i, 33)
                            // STATICCALL
                            } default {
                                let reference := calldataload(add(i, 1))
                                let pointer := add(ptr, reference)
                                let g := mload(pointer)
                                let target := mload(add(pointer, 0x20))
                                let off := mload(add(pointer, 0x40))
                                let siz := mload(add(pointer, 0x60))
                                let success := staticcall(g, target, off, siz, 0, 0)
                                let dismissRevert := mload(add(pointer, 0x80))
                                switch dismissRevert
                                case 0 {
                                    returndatacopy(ptr, 0, returndatasize())
                                    revert(0, returndatasize())
                                }
                                let dest := mload(add(pointer, 0xa0))
                                tstore(returndatasize.slot, returndatasize())
                                mstore(dest, success)
                                i := add(i, 33)
                            }
                        }
                    }
                }
            }
            caller = address(0);
            callvalue = 0;
            calldatasize = 0;
            returndatasize = 0;
        }
    }
}
