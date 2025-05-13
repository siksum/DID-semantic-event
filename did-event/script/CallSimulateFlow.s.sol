// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/DIDAuthContract.sol";

contract SimulateFlowExecutor {
    function executeFlow(
        address authAddress,
        string memory issuerDID,
        string memory vcData,
        bytes32 schemaId
    ) external {
        DIDAuthContract auth = DIDAuthContract(authAddress);
        
        auth.registerDID(issuerDID);
        auth.registerTrustedIssuer(issuerDID, schemaId);
        auth.issueCredential(vcData, issuerDID, schemaId);
        auth.logCredentialVerification(vcData, "did:example:verifier");
        auth.revokeCredential(vcData, issuerDID, "Graduated");
        auth.deactivateDID(issuerDID);
    }
}

contract CallSimulateFlow is Script {
    function run() external {
        vm.startBroadcast();

        // 1. 실행자 컨트랙트 배포
        SimulateFlowExecutor executor = new SimulateFlowExecutor();
        
        // 2. 파라미터 준비
        address authAddress = 0x703320BbBAfdc9C9C03f4a668b1F8378fac20CE9;
        string memory issuerDID = "did:example:issuer";
        uint256 timestamp = block.timestamp;
        string memory vcData = string(
            abi.encodePacked(
                "{subject:did:example:user,degree:ComputerScience,timestamp:",
                vm.toString(timestamp),
                "}"
            )
        );
        bytes32 schemaId = keccak256("UniversityCredential");
        
        // 3. 단일 트랜잭션으로 모든 작업 실행
        executor.executeFlow(authAddress, issuerDID, vcData, schemaId);

        vm.stopBroadcast();
    }
}
