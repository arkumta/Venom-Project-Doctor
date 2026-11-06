// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableTest {
    address public owner;
    uint256 public balance;

    constructor() {
        owner = msg.sender;
    }

    function withdraw() public {
        require(tx.origin == owner, "Not authorized");

        (bool success, ) = msg.sender.call{value: balance}("");

        balance = 0;
    }

    function execute(address target, bytes calldata data) public {
        target.delegatecall(data);
    }

    function destroy() public {
        selfdestruct(payable(msg.sender));
    }

    receive() external payable {}
}