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
     * @dev Copies a `bytes` value from calldata into transient storage.
     *
     * The value is stored as a length word followed by its data words. If the
     * length is not a multiple of 32 bytes, the unused bytes in the final word
     * are zeroed to produce a canonical representation.
     *
     * If the new value is shorter than the previously cached value at the same
     * namespace, trailing transient storage slots are cleared to prevent stale
     * data from remaining in the cache.
     *
     * Reverts with `TotalLengthTooLarge` if the value or previous cached value
     * exceeds `MAX_TOTAL_LENGTH`, or with `Overflow` if the transient storage
     * slot arithmetic overflows.
     *
     * @param namespace The transient storage namespace used to cache the value.
     * @param data The calldata bytes to cache.
     */
    function _setCacheCallData(bytes32 namespace, bytes calldata data) internal {
        bytes4 lengthTooLargeSelector = TotalLengthTooLarge.selector;
        bytes4 overflowSelector = Overflow.selector;
        uint64 maxTotalLength = MAX_TOTAL_LENGTH;
        assembly ("memory-safe") {
            let length := data.length
            if gt(length, maxTotalLength) {
                mstore(0, lengthTooLargeSelector)
                mstore(4, length)
                revert(0, 36)
            }
            let totalSlot := shr(5, add(length, 31))
            let cacheLength := tload(namespace)
            let totalCacheSlot
            {
                let _cacheLength := add(cacheLength, 31)
                if gt(cacheLength, _cacheLength) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                totalCacheSlot := shr(5, _cacheLength)
            }
            tstore(namespace, length)
            {
                let _namespace := add(namespace, 1)
                if gt(namespace, _namespace) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                namespace := _namespace
            }
            if length {
                let floorTotalSlot := shr(5, length)
                let lastSlot := add(namespace, floorTotalSlot)
                if gt(namespace, lastSlot) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                let offset := data.offset
                for { let i } lt(i, floorTotalSlot) { i := add(i, 1) } {
                    tstore(add(namespace, i), calldataload(add(offset, shl(5, i))))
                }
                let roundingLength := shl(5, floorTotalSlot)
                let bytesLeft := sub(length, roundingLength)
                if bytesLeft {
                    let bitsLeft := shl(3, bytesLeft)
                    let bitPadding := sub(256, bitsLeft)
                    let rawWord := calldataload(add(offset, roundingLength))
                    let mask := shl(bitPadding, shr(bitPadding, rawWord))
                    tstore(lastSlot, mask)
                }
            }
            if gt(totalCacheSlot, totalSlot) {
                if gt(cacheLength, maxTotalLength) {
                    mstore(0, lengthTooLargeSelector)
                    mstore(4, cacheLength)
                    revert(0, 36)
                }
                if gt(namespace, add(namespace, totalCacheSlot)) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                let slotLeft := sub(totalCacheSlot, totalSlot)
                namespace := add(namespace, totalSlot)
                for { let j } lt(j, slotLeft) { j := add(j, 1) } {
                    tstore(add(namespace, j), 0)
                }
            }
        }
    }

    /**
     * @dev Copies a `bytes` value from memory into transient storage.
     *
     * The value is stored as a length word followed by its data words. If the
     * length is not a multiple of 32 bytes, the unused bytes in the final word
     * are zeroed to produce a canonical representation.
     *
     * If the new value is shorter than the previously cached value at the same
     * namespace, trailing transient storage slots are cleared to prevent stale
     * data from remaining in the cache.
     *
     * Reverts with `TotalLengthTooLarge` if the value or previous cached value
     * exceeds `MAX_TOTAL_LENGTH`, or with `Overflow` if the transient storage
     * slot arithmetic overflows.
     *
     * @param namespace The transient storage namespace used to cache the value.
     * @param data The memory bytes to cache.
     */
    function _setCacheData(bytes32 namespace, bytes memory data) internal {
        bytes4 lengthTooLargeSelector = TotalLengthTooLarge.selector;
        bytes4 overflowSelector = Overflow.selector;
        uint64 maxTotalLength = MAX_TOTAL_LENGTH;
        assembly ("memory-safe") {
            let length := mload(data)
            if gt(length, maxTotalLength) {
                mstore(0, lengthTooLargeSelector)
                mstore(4, length)
                revert(0, 36)
            }
            let totalSlot := shr(5, add(length, 31))
            let cacheLength := tload(namespace)
            let totalCacheSlot := shr(5, add(cacheLength, 31))
            tstore(namespace, length)
            {
                let _namespace := add(namespace, 1)
                if gt(namespace, _namespace) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                namespace := _namespace
            }
            if length {
                let floorTotalSlot := shr(5, length)
                let lastSlot := add(namespace, floorTotalSlot)
                if gt(namespace, lastSlot) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                let offset := add(data, 32)
                for { let i } lt(i, floorTotalSlot) { i := add(i, 1) } {
                    tstore(add(namespace, i), mload(add(offset, shl(5, i))))
                }
                let roundingLength := shl(5, floorTotalSlot)
                let bytesLeft := sub(length, roundingLength)
                if bytesLeft {
                    let bitsLeft := shl(3, bytesLeft)
                    let bitPadding := sub(256, bitsLeft)
                    let rawWord := mload(add(offset, roundingLength))
                    let mask := shl(bitPadding, shr(bitPadding, rawWord))
                    tstore(lastSlot, mask)
                }
            }
            if gt(totalCacheSlot, totalSlot)  {
                if gt(cacheLength, maxTotalLength) {
                    mstore(0, lengthTooLargeSelector)
                    mstore(4, maxTotalLength)
                    revert(0, 36)
                }
                if gt(namespace, add(namespace, totalCacheSlot)) {
                    mstore(0, overflowSelector)
                    revert(0, 4)
                }
                let slotLeft := sub(totalCacheSlot, totalSlot)
                namespace := add(namespace, totalSlot)
                for { let j } lt(j, slotLeft) { j := add(j, 1) } {
                    tstore(add(namespace, j), 0)
                }
            }
        }
    }

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
        }
    }
}

abstract contract VMAccount is VMAccountBase {
    uint256 constant RETURN = 0x00;
    uint256 constant REVERT = 0x01;
    uint256 constant CALLDATACOPY = 0x02;
    uint256 constant CALLDATASIZE = 0x03;
    uint256 constant RETURNDATACOPY = 0x04;
    uint256 constant RETURNDATASIZE = 0x05;
    uint256 constant MCOPY = 0x06;
    uint256 constant TLOAD = 0x07;
    uint256 constant TSTORE = 0x08;
    uint256 constant ALLOCATE = 0x09;
    uint256 constant JUMPI = 0x0a;
    uint256 constant CALLER = 0x0b;
    uint256 constant CALLVALUE = 0x0c;
    uint256 constant CALL = 0x0d;
    uint256 constant SELFCALL = 0x0e;
    uint256 constant STATICCALL = 0x0f;
 
    function _executeCode(bytes calldata code) internal virtual override {
        bytes memory space;
        for (uint256 i = 0 ; i < code.length ; ) {
            uint8 command = uint8(code[i]);
            if (command < 8) {
                if (command < 4) {
                    if (command < 2) {
                        // RETURN
                        if (command < 1) {
                            assembly ("memory-safe") {
                                let off := calldataload(add(i, 1))
                                let siz := calldataload(add(i, 33))
                                let pos := add(space, 32)
                                return(add(pos, off), siz)
                            }
                        // REVERT
                        } else {
                            assembly ("memory-safe") {
                                let off := calldataload(add(i, 1))
                                let siz := calldataload(add(i, 33))
                                let pos := add(space, 32)
                                revert(add(pos, off), siz)
                            }
                        }
                    } else {
                        // CALLDATACOPY
                        if (command < 3) {
                            assembly ("memory-safe") {
                                let destOff := calldataload(add(i, 1))
                                let off := calldataload(add(i, 33))
                                let siz := calldataload(add(i, 65))
                                let pos := add(space, 32)
                                calldatacopy(add(pos, destOff), off, siz)
                                i := add(i, 97)
                            }
                        // CALLDATASIZE
                        } else {
                            assembly ("memory-safe") {
                                let dest := calldataload(add(i, 1))
                                let pos := add(space, 32)
                                mstore(add(pos, dest), calldatasize())
                                i := add(i, 33)
                            }
                        }
                    }
                } else {
                    if (command < 6) {
                        // RETURNDATACOPY
                        if (command < 5) {
                            assembly ("memory-safe") {
                                let destOff := calldataload(add(i, 1))
                                let off := calldataload(add(i, 33))
                                let siz := calldataload(add(i, 65))
                                let pos := add(space, 32)
                                returndatacopy(add(pos, destOff), off, siz)
                                i := add(i, 97)
                            }
                        // RETURNDATASIZE
                        } else {
                            assembly ("memory-safe") {
                                let dest := calldataload(add(i, 1))
                                let pos := add(space, 32)
                                mstore(add(pos, dest), returndatasize())
                                i := add(i, 33)
                            }
                        }
                    } else {
                        // MCOPY
                        if (command < 7) {
                            assembly ("memory-safe") {
                                let destOff := calldataload(add(i, 1))
                                let off := calldataload(add(i, 33))
                                let siz := calldataload(add(i, 65))
                                let pos := add(space, 32)
                                mcopy(add(pos, destOff), add(pos, off), siz)
                                i := add(i, 97)
                            }
                        // TLOAD
                        } else {
                            assembly ("memory-safe") {
                                let key := calldataload(add(i, 1))
                                let dest := calldataload(add(i, 33))
                                let pos := add(space, 32)
                                mstore(add(pos, dest), tload(key))
                                i := add(i, 65)
                            }
                        }
                    }
                }
            } else {
                if (command < 12) {
                    if (command < 10) {
                        // TSTORE
                        if (command < 9) {
                            assembly ("memory-safe") {
                                let key := calldataload(add(i, 1))
                                let value := calldataload(add(i, 33))
                                tstore(key, value)
                                i := add(i, 65)
                            }
                        // ALLOCATE
                        } else {
                            uint256 len;
                            assembly ("memory-safe") {
                                len := calldataload(add(i, 1))
                                i := add(i, 33)
                            }
                            space = new bytes(len);
                        }
                    } else {
                        // JUMPI
                        if (command < 11) {
                            assembly ("memory-safe") {
                                let dest := calldataload(add(i, 1))
                                let b := calldataload(add(i, 33))
                                if b { i := dest }
                            }
                        // CALLER
                        } else {
                            assembly ("memory-safe") {
                                let dest := calldataload(add(i, 1))
                                let pos := add(space, 32)
                                mstore(add(pos, dest), caller())
                                i := add(i, 33)
                            }
                        }
                    }
                } else {
                    if (command < 14) {
                        // CALLVALUE
                        if (command < 13) {
                            assembly ("memory-safe") {
                                let dest := calldataload(add(i, 1))
                                let pos := add(space, 32)
                                mstore(add(pos, dest), callvalue())
                                i := add(i, 33)
                            }
                        // CALL
                        } else {
                            bool calldataAsCode;
                            assembly ("memory-safe") {
                                calldataAsCode := iszero(iszero(calldataload(add(i, 161))))
                            }
                            if (calldataAsCode) { useCalldataAsCode = true; }
                            uint256 sliceOff;
                            assembly ("memory-safe") {
                                sliceOff := calldataload(add(i, 193))
                            }
                            offset = sliceOff;
                            uint256 sliceSiz;
                            assembly ("memory-safe") {
                                sliceSiz := calldataload(add(i, 225))
                            }
                            length = sliceSiz;
                            uint256 startOff;
                            assembly ("memory-safe") {
                                startOff := calldataload(add(i, 257))
                            }
                            address whitelister;
                            assembly ("memory-safe") {
                                whitelister := calldataload(add(i, 289))
                            }
                            unchecked {
                                bytes32 blobHash;
                                assembly ("memory-safe") {
                                    let pos := add(space, 32)
                                    blobHash := keccak256(add(pos, startOff), sliceSiz)
                                }
                                snapshotCommitment = keccak256(abi.encodePacked(
                                    abi.encode(whitelister),
                                    depth + 1,
                                    continuation + 1,
                                    blobHash
                                ));
                            }
                            assembly ("memory-safe") {
                                let g := calldataload(add(i, 1))
                                let target := calldataload(add(i, 33))
                                let value := calldataload(add(i, 65))
                                let off := calldataload(add(i, 97))
                                let siz := calldataload(add(i, 129))
                                let dest := calldataload(add(i, 321))
                                let pos := add(space, 32)
                                let success := call(g, target, value, add(pos, off), siz, 0, 0)
                                mstore(add(pos, dest), success)
                                i := add(i, 353)
                            }
                        }
                    } else {
                        // SELFCALL
                        if (command < 15) {
                            address self = THIS_ADDRESS;
                            assembly ("memory-safe") {
                                let g := calldataload(add(i, 1))
                                let off := calldataload(add(i, 33))
                                let siz := calldataload(add(i, 65))
                                let dest := calldataload(add(i, 97))
                                let pos := add(space, 32)
                                let success := delegatecall(g, self, off, siz, 0, 0)
                                mstore(add(pos, dest), success)
                                i := add(i, 129)
                            }
                        // STATICCALL
                        } else {
                            assembly ("memory-safe") {
                                let g := calldataload(add(i, 1))
                                let target := calldataload(add(i, 33))
                                let off := calldataload(add(i, 65))
                                let siz := calldataload(add(i, 97))
                                let dest := calldataload(add(i, 129))
                                let pos := add(space, 32)
                                let success := staticcall(g, target, off, siz, 0, 0)
                                mstore(add(pos, dest), success)
                                i := add(i, 161)
                            }
                        }
                    }
                }
            }
        }
    }
}
