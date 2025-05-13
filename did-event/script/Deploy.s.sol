// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/DIDAuthContract.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast(); // signer 활성화

        DIDAuthContract auth = new DIDAuthContract();

        console.log("Contract deployed at:", address(auth));

        vm.stopBroadcast();
    }
}
