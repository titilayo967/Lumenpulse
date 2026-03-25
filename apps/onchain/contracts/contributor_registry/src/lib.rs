#![no_std]

mod errors;
mod events;
mod multisig;
mod storage;

use errors::ContributorError;
use events::{AdminChangedEvent, MultisigConfiguredEvent, UpgradedEvent};
use multisig::{
    cancel, consume_approval, expire, get_config, get_proposal, propose, sign, validate_config,
    MultisigConfig, ProposalAction, ProposalStatus, Signer,
};
use notification_interface::{Notification, NotificationReceiverTrait};
use soroban_sdk::xdr::FromXdr;
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String, Symbol, Vec};
use storage::{ContributorData, DataKey};

#[contract]
pub struct ContributorRegistryContract;

#[contractimpl]
impl ContributorRegistryContract {
    // ── Helpers ──────────────────────────────────────────────

    fn ensure_github_handle_available(
        env: &Env,
        github_handle: &String,
        address: &Address,
    ) -> Result<(), ContributorError> {
        if let Some(existing_address) = env
            .storage()
            .persistent()
            .get::<_, Address>(&DataKey::GitHubIndex(github_handle.clone()))
        {
            if existing_address != *address {
                return Err(ContributorError::GitHubHandleTaken);
            }
        }
        Ok(())
    }

    // ── Initialisation ───────────────────────────────────────

    pub fn initialize(
        env: Env,
        signers: Vec<Signer>,
        threshold: u32,
    ) -> Result<(), ContributorError> {
        if env.storage().instance().has(&DataKey::MultisigConfig) {
            return Err(ContributorError::AlreadyInitialized);
        }

        validate_config(&signers, threshold)?;

        let bootstrapper = signers
            .get(0)
            .ok_or(ContributorError::InvalidMultisigConfig)?;
        bootstrapper.address.require_auth();

        let config = MultisigConfig {
            signers: signers.clone(),
            threshold,
        };
        env.storage()
            .instance()
            .set(&DataKey::MultisigConfig, &config);
        env.storage()
            .instance()
            .set(&DataKey::NextProposalId, &0u64);

        MultisigConfiguredEvent {
            configured_by: bootstrapper.address.clone(),
            threshold,
            signer_count: signers.len() as u32,
        }
        .publish(&env);

        Ok(())
    }

    // ── Multisig proposal lifecycle ──────────────────────────

    /// Create a new proposal for a sensitive action.
    /// The proposer must be a registered signer; their weight is
    /// immediately counted (proposing = signing).
    pub fn propose(
        env: Env,
        proposer: Address,
        action: ProposalAction,
    ) -> Result<u64, ContributorError> {
        propose(&env, proposer, action)
    }

    /// Add a signature to an existing proposal.
    pub fn sign(
        env: Env,
        signer: Address,
        proposal_id: u64,
    ) -> Result<ProposalStatus, ContributorError> {
        sign(&env, signer, proposal_id)
    }

    /// Cancel a pending or approved proposal.
    /// Any registered signer may cancel.
    pub fn cancel_proposal(
        env: Env,
        signer: Address,
        proposal_id: u64,
    ) -> Result<(), ContributorError> {
        cancel(&env, signer, proposal_id)
    }

    /// Expire a proposal that has passed its TTL.
    /// Permissionless.
    pub fn expire_proposal(env: Env, proposal_id: u64) -> Result<(), ContributorError> {
        expire(&env, proposal_id)
    }

    /// Replace the entire signer set and threshold.
    /// Guarded by an approved `SetAdmin` proposal.
    pub fn set_multisig_config(
        env: Env,
        executor: Address,
        proposal_id: u64,
        new_signers: Vec<Signer>,
        new_threshold: u32,
    ) -> Result<(), ContributorError> {
        consume_approval(&env, &executor, proposal_id, &ProposalAction::SetAdmin)?;

        validate_config(&new_signers, new_threshold)?;

        let config = MultisigConfig {
            signers: new_signers.clone(),
            threshold: new_threshold,
        };
        env.storage()
            .instance()
            .set(&DataKey::MultisigConfig, &config);

        MultisigConfiguredEvent {
            configured_by: executor,
            threshold: new_threshold,
            signer_count: new_signers.len() as u32,
        }
        .publish(&env);

        Ok(())
    }

    // ── Contributor operations ───────────────────────────────

    /// Register a new contributor with their GitHub handle.
    pub fn register_contributor(
        env: Env,
        address: Address,
        github_handle: String,
    ) -> Result<(), ContributorError> {
        if !env.storage().instance().has(&DataKey::MultisigConfig) {
            return Err(ContributorError::NotInitialized);
        }
        address.require_auth();
        if github_handle.is_empty() {
            return Err(ContributorError::InvalidGitHubHandle);
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::Contributor(address.clone()))
        {
            return Err(ContributorError::ContributorAlreadyExists);
        }
        Self::ensure_github_handle_available(&env, &github_handle, &address)?;
        let timestamp = env.ledger().timestamp();
        let contributor = ContributorData {
            address: address.clone(),
            github_handle: github_handle.clone(),
            reputation_score: 0,
            registered_timestamp: timestamp,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Contributor(address.clone()), &contributor);
        env.storage()
            .persistent()
            .set(&DataKey::GitHubIndex(github_handle), &address);
        Ok(())
    }

    /// Update an existing contributor's GitHub handle.
    pub fn update_contributor(
        env: Env,
        address: Address,
        github_handle: String,
    ) -> Result<(), ContributorError> {
        if !env.storage().instance().has(&DataKey::MultisigConfig) {
            return Err(ContributorError::NotInitialized);
        }
        address.require_auth();
        if github_handle.is_empty() {
            return Err(ContributorError::InvalidGitHubHandle);
        }
        let mut contributor: ContributorData = env
            .storage()
            .persistent()
            .get(&DataKey::Contributor(address.clone()))
            .ok_or(ContributorError::ContributorNotFound)?;

        Self::ensure_github_handle_available(&env, &github_handle, &address)?;
        if contributor.github_handle != github_handle {
            env.storage()
                .persistent()
                .remove(&DataKey::GitHubIndex(contributor.github_handle.clone()));
        }
        contributor.github_handle = github_handle.clone();
        env.storage()
            .persistent()
            .set(&DataKey::Contributor(address.clone()), &contributor);
        env.storage()
            .persistent()
            .set(&DataKey::GitHubIndex(github_handle), &address);
        Ok(())
    }

    // ── Sensitive functions — multisig-gated ─────────────────

    /// Update a contributor's reputation score.
    /// Requires an approved `UpdateReputation` proposal.
    pub fn update_reputation(
        env: Env,
        executor: Address,
        proposal_id: u64,
        contributor_address: Address,
        delta: i64,
    ) -> Result<(), ContributorError> {
        consume_approval(
            &env,
            &executor,
            proposal_id,
            &ProposalAction::UpdateReputation,
        )?;

        let mut contributor: ContributorData = env
            .storage()
            .persistent()
            .get(&DataKey::Contributor(contributor_address.clone()))
            .ok_or(ContributorError::ContributorNotFound)?;

        let new_score = if delta > 0 {
            contributor
                .reputation_score
                .checked_add(delta as u64)
                .ok_or(ContributorError::ReputationOverflow)?
        } else {
            let abs = delta.checked_abs().unwrap_or(0) as u64;
            contributor.reputation_score.saturating_sub(abs)
        };
        contributor.reputation_score = new_score;
        env.storage()
            .persistent()
            .set(&DataKey::Contributor(contributor_address), &contributor);
        Ok(())
    }

    /// Upgrade the contract WASM.
    /// Requires an approved `Upgrade` proposal.
    pub fn upgrade(
        env: Env,
        executor: Address,
        proposal_id: u64,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), ContributorError> {
        consume_approval(&env, &executor, proposal_id, &ProposalAction::Upgrade)?;

        env.deployer()
            .update_current_contract_wasm(new_wasm_hash.clone());

        UpgradedEvent {
            admin: executor,
            new_wasm_hash,
        }
        .publish(&env);

        Ok(())
    }

    /// Transfer admin designation to a new address.
    /// Requires an approved `SetAdmin` proposal.
    pub fn set_admin(
        env: Env,
        executor: Address,
        proposal_id: u64,
        new_admin: Address,
    ) -> Result<(), ContributorError> {
        consume_approval(&env, &executor, proposal_id, &ProposalAction::SetAdmin)?;

        env.storage().instance().set(&DataKey::Admin, &new_admin);

        AdminChangedEvent {
            old_admin: executor,
            new_admin,
        }
        .publish(&env);

        Ok(())
    }

    // ── Queries ──────────────────────────────────────────────

    pub fn get_reputation(env: Env, contributor: Address) -> Result<u64, ContributorError> {
        Ok(Self::get_contributor(env, contributor)?.reputation_score)
    }

    pub fn get_contributor(
        env: Env,
        address: Address,
    ) -> Result<ContributorData, ContributorError> {
        env.storage()
            .persistent()
            .get(&DataKey::Contributor(address))
            .ok_or(ContributorError::ContributorNotFound)
    }

    pub fn get_contributor_by_github(
        env: Env,
        github_handle: String,
    ) -> Result<ContributorData, ContributorError> {
        let address: Address = env
            .storage()
            .persistent()
            .get(&DataKey::GitHubIndex(github_handle))
            .ok_or(ContributorError::ContributorNotFound)?;
        Self::get_contributor(env, address)
    }

    pub fn get_multisig_config(env: Env) -> Result<MultisigConfig, ContributorError> {
        get_config(&env)
    }

    pub fn get_proposal(
        env: Env,
        proposal_id: u64,
    ) -> Result<multisig::Proposal, ContributorError> {
        get_proposal(&env, proposal_id)
    }

    pub fn get_next_proposal_id(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::NextProposalId)
            .unwrap_or(0)
    }
}

// ── Notification receiver (project owner's addition) ─────────

#[contractimpl]
impl NotificationReceiverTrait for ContributorRegistryContract {
    fn on_notify(env: Env, notification: Notification) {
        // Only react to "deposit" events
        if notification.event_type == Symbol::new(&env, "deposit") {
            // Unpack data: (user: Address, project_id: u64, amount: i128)
            let (user, _project_id, _amount): (Address, u64, i128) =
                <(Address, u64, i128)>::from_xdr(&env, &notification.data).unwrap();

            // Award 1 reputation point per deposit if contributor is registered.
            if let Some(mut contributor) = env
                .storage()
                .persistent()
                .get::<_, ContributorData>(&DataKey::Contributor(user.clone()))
            {
                contributor.reputation_score = contributor.reputation_score.saturating_add(1);
                env.storage()
                    .persistent()
                    .set(&DataKey::Contributor(user), &contributor);
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{testutils::Address as TestAddress, Address, Env, Vec};

    struct Setup {
        env: Env,
        contract: Address,
        alice: Address,
        bob: Address,
        carol: Address,
    }

    fn setup() -> Setup {
        let env = Env::default();
        env.mock_all_auths();
        let contract = env.register_contract(None, ContributorRegistryContract);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let carol = Address::generate(&env);

        let mut signers = Vec::new(&env);
        signers.push_back(Signer {
            address: alice.clone(),
            weight: 2,
        });
        signers.push_back(Signer {
            address: bob.clone(),
            weight: 1,
        });
        signers.push_back(Signer {
            address: carol.clone(),
            weight: 1,
        });

        let client = ContributorRegistryContractClient::new(&env, &contract);
        client.initialize(&signers, &3u32);

        Setup {
            env,
            contract,
            alice,
            bob,
            carol,
        }
    }

    #[test]
    fn test_initialize_stores_config() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);
        let config = client.get_multisig_config().unwrap();
        assert_eq!(config.threshold, 3);
        assert_eq!(config.signers.len(), 3);
    }

    #[test]
    fn test_double_initialize_fails() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);
        let mut signers = Vec::new(&s.env);
        signers.push_back(Signer {
            address: s.alice.clone(),
            weight: 1,
        });
        assert!(client.try_initialize(&signers, &1u32).is_err());
    }

    #[test]
    fn test_threshold_above_total_weight_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract = env.register_contract(None, ContributorRegistryContract);
        let client = ContributorRegistryContractClient::new(&env, &contract);
        let alice = Address::generate(&env);

        let mut signers = Vec::new(&env);
        signers.push_back(Signer {
            address: alice,
            weight: 1,
        });
        assert!(client.try_initialize(&signers, &99u32).is_err());
    }

    #[test]
    fn test_propose_counts_proposer_weight() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);

        let id = client.propose(&s.alice, &ProposalAction::Upgrade).unwrap();
        let proposal = client.get_proposal(&id).unwrap();

        assert_eq!(proposal.weight_collected, 2);
        assert_eq!(proposal.status, ProposalStatus::Pending);
    }

    #[test]
    fn test_propose_by_non_signer_fails() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);
        let outsider = Address::generate(&s.env);
        assert!(client
            .try_propose(&outsider, &ProposalAction::Upgrade)
            .is_err());
    }

    #[test]
    fn test_single_signer_above_threshold_auto_approves() {
        let env = Env::default();
        env.mock_all_auths();
        let contract = env.register_contract(None, ContributorRegistryContract);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        let mut signers = Vec::new(&env);
        signers.push_back(Signer {
            address: alice.clone(),
            weight: 3,
        });
        signers.push_back(Signer {
            address: bob.clone(),
            weight: 1,
        });

        let client = ContributorRegistryContractClient::new(&env, &contract);
        client.initialize(&signers, &3u32);

        let id = client.propose(&alice, &ProposalAction::Upgrade).unwrap();
        let proposal = client.get_proposal(&id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Approved);
    }

    #[test]
    fn test_sign_reaches_threshold() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);

        let id = client.propose(&s.alice, &ProposalAction::Upgrade).unwrap();
        let status = client.sign(&s.bob, &id).unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn test_double_sign_rejected() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);

        let id = client.propose(&s.bob, &ProposalAction::Upgrade).unwrap();
        assert!(client.try_sign(&s.bob, &id).is_err());
    }

    #[test]
    fn test_non_signer_cannot_sign() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);
        let outsider = Address::generate(&s.env);

        let id = client.propose(&s.alice, &ProposalAction::Upgrade).unwrap();
        assert!(client.try_sign(&outsider, &id).is_err());
    }

    #[test]
    fn test_bob_carol_together_cannot_reach_threshold() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);

        let id = client.propose(&s.bob, &ProposalAction::Upgrade).unwrap();
        client.sign(&s.carol, &id).unwrap();

        let proposal = client.get_proposal(&id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Pending);
    }

    #[test]
    fn test_upgrade_executes_after_approval() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);

        let id = client.propose(&s.alice, &ProposalAction::Upgrade).unwrap();
        client.sign(&s.bob, &id).unwrap();

        let wasm_hash = BytesN::from_array(&s.env, &[1u8; 32]);
        let _ = client.try_upgrade(&s.alice, &id, &wasm_hash);
        let proposal = client.get_proposal(&id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Executed);
    }

    #[test]
    fn test_execute_below_threshold_fails() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);

        let id = client.propose(&s.bob, &ProposalAction::Upgrade).unwrap();
        let wasm_hash = BytesN::from_array(&s.env, &[1u8; 32]);
        assert!(client.try_upgrade(&s.bob, &id, &wasm_hash).is_err());
    }

    #[test]
    fn test_wrong_action_type_rejected() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);

        let id = client.propose(&s.alice, &ProposalAction::Upgrade).unwrap();
        client.sign(&s.bob, &id).unwrap();

        let new_admin = Address::generate(&s.env);
        assert!(client.try_set_admin(&s.alice, &id, &new_admin).is_err());
    }

    #[test]
    fn test_replay_blocked_after_execution() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);

        let id = client.propose(&s.alice, &ProposalAction::Upgrade).unwrap();
        client.sign(&s.bob, &id).unwrap();
        let wasm_hash = BytesN::from_array(&s.env, &[1u8; 32]);
        let _ = client.try_upgrade(&s.alice, &id, &wasm_hash);

        assert!(client.try_upgrade(&s.alice, &id, &wasm_hash).is_err());
    }

    #[test]
    fn test_update_reputation_requires_multisig() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);

        let contributor = Address::generate(&s.env);
        let handle = soroban_sdk::String::from_str(&s.env, "dev_handle");
        client.register_contributor(&contributor, &handle).unwrap();

        let fake_id = 999u64;
        assert!(client
            .try_update_reputation(&s.alice, &fake_id, &contributor, &10i64)
            .is_err());
    }

    #[test]
    fn test_update_reputation_succeeds_with_approval() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);

        let contributor = Address::generate(&s.env);
        let handle = soroban_sdk::String::from_str(&s.env, "dev_handle");
        client.register_contributor(&contributor, &handle).unwrap();

        let id = client
            .propose(&s.alice, &ProposalAction::UpdateReputation)
            .unwrap();
        client.sign(&s.bob, &id).unwrap();

        client
            .update_reputation(&s.alice, &id, &contributor, &50i64)
            .unwrap();

        assert_eq!(client.get_reputation(&contributor).unwrap(), 50);
    }

    #[test]
    fn test_cancel_blocks_execution() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);

        let id = client.propose(&s.alice, &ProposalAction::Upgrade).unwrap();
        client.sign(&s.bob, &id).unwrap();
        client.cancel_proposal(&s.alice, &id).unwrap();

        let wasm_hash = BytesN::from_array(&s.env, &[1u8; 32]);
        assert!(client.try_upgrade(&s.alice, &id, &wasm_hash).is_err());
    }

    #[test]
    fn test_expire_after_ttl() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);

        s.env.ledger().set_timestamp(1_000_000);
        let id = client.propose(&s.alice, &ProposalAction::Upgrade).unwrap();

        s.env
            .ledger()
            .set_timestamp(1_000_000 + multisig::PROPOSAL_TTL_SECS + 1);

        client.expire_proposal(&id).unwrap();

        let proposal = client.get_proposal(&id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Expired);
    }

    #[test]
    fn test_expire_before_ttl_fails() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);

        s.env.ledger().set_timestamp(1_000_000);
        let id = client.propose(&s.alice, &ProposalAction::Upgrade).unwrap();
        s.env.ledger().set_timestamp(1_000_000 + 3600);

        assert!(client.try_expire_proposal(&id).is_err());
    }

    #[test]
    fn test_full_upgrade_proposal_flow() {
        let s = setup();
        let client = ContributorRegistryContractClient::new(&s.env, &s.contract);

        let id = client.propose(&s.alice, &ProposalAction::Upgrade).unwrap();
        assert_eq!(
            client.get_proposal(&id).unwrap().status,
            ProposalStatus::Pending
        );

        let status = client.sign(&s.bob, &id).unwrap();
        assert_eq!(status, ProposalStatus::Approved);

        let status = client.sign(&s.carol, &id).unwrap();
        assert_eq!(status, ProposalStatus::Approved);

        let wasm_hash = BytesN::from_array(&s.env, &[0xabu8; 32]);
        let _ = client.try_upgrade(&s.alice, &id, &wasm_hash);
        assert_eq!(
            client.get_proposal(&id).unwrap().status,
            ProposalStatus::Executed
        );

        assert!(client.try_upgrade(&s.alice, &id, &wasm_hash).is_err());
    }
}
