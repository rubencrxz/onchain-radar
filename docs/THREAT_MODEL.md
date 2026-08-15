# Threat Model

The MVP focuses on observable administrative and operational risk signals in Ethereum protocols.

## Initial Risk Categories

- Privileged role compromise.
- Ownership transfer.
- Admin action abuse.
- Protocol pause or unpause.
- Proxy upgrade risk.
- Multisig execution risk.
- Emergency protocol state changes.

These risks matter because privileged actions can change protocol behavior, redirect control, disable functionality, or prepare malicious upgrades.

The MVP does not try to prove that an exploit is happening. It detects events that are important enough for human review.

## Future Risk Categories

- Oracle manipulation.
- Liquidity drain.
- Pool imbalance.
- Abnormal withdrawals.
- Cross-chain message compromise.
- Bridge/DVN risk.
- RPC or infrastructure degradation.

These future categories require more context, protocol-specific modeling, or infrastructure monitoring. They are deferred until the deterministic MVP is working.
