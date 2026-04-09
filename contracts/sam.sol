// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

contract Sanam {
    mapping(address => uint256) public balance;
    function give_some(uint256 amount_to_receive) public  {
        require(balance[msg.sender]>=amount_to_receive,"Not enough balance");
        (bool success,) = msg.sender.call{value: amount_to_receive}("");
        require(success, "Transfer failed");
        balance[msg.sender] -= amount_to_receive;
    }
}