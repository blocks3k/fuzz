// SPDX-License-Identifier: MIT
pragma solidity ^0.8.2;

contract OptimismPortal{

}
contract MockL2Oracle{

}
contract MockSecureMerkleTrie{}

contract ProveWithdrawalTransactionTest{
    OptimismPortal portal;
    MockL2Oracle l2Oracle;
    MockSecureMerkleTrie merkleTrie;

    // Needed so the test contract itself can receive ether
    // when withdrawing
    receive() external payable {}

    function setUp() public {
        portal = new OptimismPortal();
        l2Oracle = new MockL2Oracle();
        merkleTrie = new MockSecureMerkleTrie();
        // Connect your portal with mock L2Oracle and SecureMerkleTrie here
    }

    function generateRandomWithdrawalTransaction() internal returns (Types.WithdrawalTransaction memory) {
        uint256 nonce = uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
        address sender = address(uint160(uint256(keccak256(abi.encodePacked(nonce)))));
        address target = address(uint160(uint256(keccak256(abi.encodePacked(sender)))));
        uint256 value = uint256(keccak256(abi.encodePacked(target)));
        uint256 gasLimit = uint256(keccak256(abi.encodePacked(value)));
        bytes memory data = abi.encodePacked(gasLimit);

        return Types.WithdrawalTransaction({
            nonce: nonce,
            sender: sender,
            target: target,
            value: value,
            gasLimit: gasLimit,
            data: data
        });
    }

    function generateRandomOutputRootProof() internal returns (Types.OutputRootProof memory) {
        bytes32 version = keccak256(abi.encodePacked(block.timestamp, block.difficulty));
        bytes32 stateRoot = keccak256(abi.encodePacked(version));
        bytes32 messagePasserStorageRoot = keccak256(abi.encodePacked(stateRoot));
        bytes32 latestBlockhash = keccak256(abi.encodePacked(messagePasserStorageRoot));

        return Types.OutputRootProof({
            version: version,
            stateRoot: stateRoot,
            messagePasserStorageRoot: messagePasserStorageRoot,
            latestBlockhash: latestBlockhash
        });
    }

    function generateRandomWithdrawalProof(
        address _target,
        uint256 _gasLimit,
        bytes memory _data
    ) public payable returns (bytes calldata) {
        bytes calldata withdrawalHash = Hashing.hashWithdrawal(
            Types.WithdrawalTransaction({
                nonce: block.timestamp,
                sender: msg.sender,
                target: _target,
                value: msg.value,
                gasLimit: _gasLimit,
                data: _data
            })
        );
        return withdrawalHash;
    }

    function test_proveWithdrawalTransaction(
        address _target,
        uint256 _gasLimit,
        bytes memory _data
        ) public {
        // Generate random inputs for your function.
        Types.WithdrawalTransaction memory _tx = generateRandomWithdrawalTransaction();
        uint256 _l2OutputIndex = uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
        Types.OutputRootProof memory _outputRootProof = generateRandomOutputRootProof();
        bytes[] calldata _withdrawalProof = generateRandomWithdrawalProof(_target,_gasLimit,_data);

        // Call your function
        portal.proveWithdrawalTransaction(_tx, _l2OutputIndex, _outputRootProof, _withdrawalProof);

        // Check post-conditions, state changes, or events emitted as needed.
        // Again, this will depend on the specifics of your contract.
    }
}


library Types {

    /**
     * @notice Struct representing a withdrawal transaction.
     *
     * @custom:field nonce    Nonce of the withdrawal transaction
     * @custom:field sender   Address of the sender of the transaction.
     * @custom:field target   Address of the recipient of the transaction.
     * @custom:field value    Value to send to the recipient.
     * @custom:field gasLimit Gas limit of the transaction.
     * @custom:field data     Data of the transaction.
     */

    struct WithdrawalTransaction {
        uint256 nonce;
        address sender;
        address target;
        uint256 value;
        uint256 gasLimit;
        bytes data;
    }

        /**
     * @notice Struct representing the elements that are hashed together to generate an output root
     *         which itself represents a snapshot of the L2 state.
     *
     * @custom:field version                  Version of the output root.
     * @custom:field stateRoot                Root of the state trie at the block of this output.
     * @custom:field messagePasserStorageRoot Root of the message passer storage trie.
     * @custom:field latestBlockhash          Hash of the block this output was generated from.
     */
    struct OutputRootProof {
        bytes32 version;
        bytes32 stateRoot;
        bytes32 messagePasserStorageRoot;
        bytes32 latestBlockhash;
    }
}

library Hashing {
        function hashWithdrawal(Types.WithdrawalTransaction memory _tx)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(_tx.nonce, _tx.sender, _tx.target, _tx.value, _tx.gasLimit, _tx.data)
            );
    }

}

