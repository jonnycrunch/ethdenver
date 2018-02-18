pragma solidity ^0.4.18;

contract ShardStore {

    event StorageConfirmed(
        address trustedContact,
        uint shardId
        );

    function confirmStorage(uint shardId) public {
        StorageConfirmed(msg.sender, shardId);
    }

    /* FUTURE WORK FOR EVALUATION
    - Do we want to create a mapping of addresses that are allowed
    to call confirmStorage? Right now a small attack vector exists
    where a malicious actor could confirm storage of a particular
    shardId even though the true user is not confirming that and may
    no longer have the ID.
    */
}
