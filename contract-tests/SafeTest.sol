// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SafeTest {
    address public owner;
    uint256 public balance;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balance += msg.value;
    }

    function withdraw() public {
        require(msg.sender == owner, "Not authorized");

        uint256 amount = balance;
        balance = 0;

        (bool success, ) = payable(owner).call{value: amount}("");
        require(success, "Transfer failed");
    }
}