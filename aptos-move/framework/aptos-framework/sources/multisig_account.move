/// Enhanced multisig account standard on Aptos. This is different from the native multisig scheme support enforced via
/// the account's auth key.
///
/// This module allows creating a flexible and powerful multisig account with seamless support for updating owners
/// without changing the auth key. Users can choose to store transaction payloads waiting for owner signatures on chain
/// or off chain (primary consideration is decentralization/transparency vs gas cost).
///
/// The multisig account is a resource account underneath. By default, it has no auth key and can only be controlled via
/// the special multisig transaction flow. However, owners can create a transaction to change the auth key to match a
/// private key off chain if so desired.
///
/// Transactions need to be executed in order of creation, similar to transactions for a normal Aptos account (enforced
/// with acount nonce).
///
/// The flow is like below:
/// 1. Owners can create a new multisig account by calling create (signer is default single owner) or with
/// create_with_owners where multiple initial owner addresses can be specified. This is different (and easier) from
/// the native multisig scheme where the owners' public keys have to be specified. Here, only addresses are needed.
/// 2. Owners can be added/removed any time by calling add_owners or remove_owners. The transactions to do still need
/// to follow the k-of-n scheme specified for the multisig account.
/// 3. To create a new transaction, an owner can call create_transaction with the transaction payload: specified module
/// (address + name), the name of the function to call, and argument values. This will store the full transaction
/// payload on chain, which adds decentralization (censorship is not possible) and makes it easier to fetch all
/// transactions waiting for execution. If saving gas is desired, an owner can alternatively call
/// create_transaction_with_hash where only the payload hash is stored (module + function + args). Later execution will
/// be verified using the hash. Only owners can create transactions and a transaction id (incremeting id) will be
/// assigned.
/// 4. To approve or reject a transaction, other owners can call approve() or reject() with the transaction id.
/// 5. If there are enough approvals, any owner can execute the transaction using the special MultisigTransaction type
/// with the transaction id if the full payload is already stored on chain or with the transaction payload if only a
/// hash is stored. Transaction execution will first check with this module that the transaction payload has gotten
/// enough signatures. If so, it will be executed as the multisig account. The owner who executes will pay for gas.
/// 6. If there are enough rejections, any owner can remove the transaction by calling remove().
module aptos_framework::multisig_account {
    use aptos_framework::account::{Self, SignerCapability, new_event_handle, create_resource_address};
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::coin;
    use aptos_framework::event::{EventHandle, emit_event};
    use aptos_std::simple_map::{Self, SimpleMap};
    use aptos_std::table::{Self, Table};
    use std::bcs::to_bytes;
    use std::error;
    use std::hash::sha3_256;
    use std::option::{Self, Option};
    use std::signer::address_of;
    use std::string::{Self, String};
    use std::vector;

    /// The salt used to create a resource account during multisig account creation.
    /// This is used to avoid conflicts with other modules that also create resource accounts with the same owner
    /// account.
    const DOMAIN_SEPARATOR: vector<u8> = b"aptos_framework::multisig_account";

    /// Owner list cannot contain the same address more than once.
    const EDUPLICATE_OWNER: u64 = 1;
    /// Specified account is not a multisig account.
    const EACCOUNT_NOT_MULTISIG: u64 = 2;
    /// Account executing this operation is not an owner of the multisig account.
    const ENOT_OWNER: u64 = 3;
    /// Target function cannot be empty.
    const ETARGET_FUNCTION_CANNOT_BE_EMPTY: u64 = 4;
    /// Multisig account must have at least one owner.
    const ENOT_ENOUGH_OWNERS: u64 = 5;
    /// Function hash must be exactly 32 bytes (sha3-256).
    const EINVALID_FUNCTION_HASH: u64 = 6;
    /// Transaction with specified id cannot be found. It either has not been created or has already been executed.
    const ETRANSACTION_NOT_FOUND: u64 = 7;
    /// Cannot execute the specified transaction simply via transaction_id as the full payload is not stored on chain.
    const EPAYLOAD_NOT_STORED: u64 = 8;
    /// Provided target function does not match the hash stored in the on-chain transaction.
    const ETARGET_FUNCTION_DOES_NOT_MATCH_HASH: u64 = 9;
    /// Provided arguments do not match the hash stored in the on-chain transaction.
    const EARGUMENTS_DOES_NOT_MATCH_HASH: u64 = 10;
    /// Transaction has not received enough approvals to be executed.
    const ENOT_ENOUGH_APPROVALS: u64 = 11;
    /// Transaction has not received enough rejections to be removed.
    const ENOT_ENOUGH_REJECTIONS: u64 = 12;
    /// Number of signatures required must be more than zero and at most the total number of owners.
    const EINVALID_SIGNATURES_REQUIRED: u64 = 13;
    /// Function args hash must be exactly 32 bytes (sha3-256).
    const EINVALID_FUNCTION_ARGS_HASH: u64 = 14;
    /// The multisig account itself cannot be an owner.
    const EOWNER_CANNOT_BE_MULTISIG_ACCOUNT_ITSELF: u64 = 15;
    /// Owner has already approved this transaction before.
    const TRANSACTION_HAS_ALREADY_BEEN_APPROVED: u64 = 16;
    /// Owner has already rejected this transaction before.
    const TRANSACTION_HAS_ALREADY_BEEN_REJECTED: u64 = 17;

    /// Represents a multisig account's configurations and transactions.
    /// This will be stored in the multisig account (created as a resource account separate from any owner accounts).
    struct MultisigAccount has key {
        // The list of all owner addresses.
        owners: vector<address>,
        // The number of signatures required to pass a transaction (k in k-of-n).
        signatures_required: u64,
        // Map from transaction id (incrementing id) to transactions to execute for this multisig account.
        // Already executed transactions are deleted to save on storage but can always be accessed via events.
        transactions: Table<u64, MultisigTransaction>,
        // Last executed or rejected transaction id. Used to enforce in-order executions of proposals.
        last_transaction_id: u64,
        // The transaction id to assign to the next transaction.
        next_transaction_id: u64,
        // The signer capability controlling the multisig (resource) account. This can be exchanged for the signer.
        // Currently not used as the MultisigTransaction can validate and create a signer directly in the VM but
        // this can be useful to have for on-chain composability in the future.
        signer_cap: Option<SignerCapability>,

        // Events.
        add_owners_events: EventHandle<AddOwnersEvent>,
        remove_owners_events: EventHandle<RemoveOwnersEvent>,
        update_signature_required_events: EventHandle<UpdateSignaturesRequiredEvent>,
        create_transaction_events: EventHandle<CreateTransactionEvent>,
        approve_transaction_events: EventHandle<ApproveTransactionEvent>,
        reject_transaction_events: EventHandle<RejectTransactionEvent>,
        execute_transaction_events: EventHandle<ExecuteTransactionEvent>,
        remove_transaction_events: EventHandle<RemoveTransactionEvent>,
    }

    /// A transaction to be executed in a multisig account.
    /// This must contain either the full transaction payload or its hash (stored as bytes).
    struct MultisigTransaction has copy, drop, store {
        payload: Option<TransactionPayload>,
        payload_hash: Option<PayloadHash>,
        // Owners who have approved. Uses a simple map to deduplicate.
        approvals: SimpleMap<address, bool>,
        // Owners who have rejected. Uses a simple map to deduplicate.
        rejections: SimpleMap<address, bool>,
        // The owner who created this transaction.
        creator: address,
        // Metadata about the transaction such as description, etc.
        // This can also be reused in the future to add new attributes to multisig transactions such as expiration time.
        metadata: SimpleMap<String, vector<u8>>,
    }

    /// The payload of the transaction to store on chain.
    struct TransactionPayload has copy, drop, store {
        // The target function to call such as 0x123::module_to_call::function_to_call.
        target_function: String,
        // BCS-encoded argument values to invoke the target function with.
        args: vector<u8>,
    }

    /// The hash of the multisig transaction payload.
    struct PayloadHash has copy, drop, store {
        // Hash of the function to call
        function_hash: vector<u8>,
        // Hash of the arguments, concatenated in the right order.
        args_hash: vector<u8>,
    }

    /// Used only for vierfying multisig account creation on top of existing accounts.
    struct MultisigAccountCreationMessage has copy, drop {
        // Chain id is included to prevent cross-chain replay.
        chain_id: u8,
    }

    /// Event emitted when new owners are added to the multisig account.
    struct AddOwnersEvent has drop, store {
        owners_added: vector<address>,
    }

    /// Event emitted when new owners are removed from the multisig account.
    struct RemoveOwnersEvent has drop, store {
        owners_removed: vector<address>,
    }

    /// Event emitted when the number of signatures required is updated.
    struct UpdateSignaturesRequiredEvent has drop, store {
        old_signatures_required: u64,
        new_signatures_required: u64,
    }

    /// Event emitted when a transaction is created.
    struct CreateTransactionEvent has drop, store {
        transaction_id: u64,
        transaction: MultisigTransaction,
    }

    /// Event emitted when an owner approves a transaction.
    struct ApproveTransactionEvent has drop, store {
        transaction_id: u64,
        owner: address,
        num_approvals: u64,
    }

    /// Event emitted when an owner rejects a transaction.
    struct RejectTransactionEvent has drop, store {
        transaction_id: u64,
        owner: address,
        num_rejections: u64,
    }

    /// Event emitted when a transaction is officially removed because the number of rejections has reached the
    /// number of signatures required.
    struct RemoveTransactionEvent has drop, store {
        transaction_id: u64,
        num_rejections: u64,
        executor: address,
    }

    /// Event emitted when a transaction is executed.
    struct ExecuteTransactionEvent has drop, store {
        transaction_id: u64,
        transaction_payload: TransactionPayload,
        num_approvals: u64,
        executor: address,
    }

    #[view]
    public fun signatures_required(multisig_account: address): u64 acquires MultisigAccount {
        borrow_global<MultisigAccount>(multisig_account).signatures_required
    }

    #[view]
    public fun owners(multisig_account: address): vector<address> acquires MultisigAccount {
        borrow_global<MultisigAccount>(multisig_account).owners
    }

    #[view]
    public fun get_transaction(
        multisig_account: address,
        transaction_id: u64,
    ): MultisigTransaction acquires MultisigAccount {
        *table::borrow(&borrow_global<MultisigAccount>(multisig_account).transactions, transaction_id)
    }

    #[view]
    public fun can_be_executed(
        multisig_account: address, transaction_id: u64): bool acquires MultisigAccount {
        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
        let transaction = table::borrow(&mut multisig_account_resource.transactions, transaction_id);
        transaction_id == multisig_account_resource.last_transaction_id + 1 &&
            simple_map::length(&transaction.approvals) >= multisig_account_resource.signatures_required
    }

    #[view]
    public fun can_be_removed(
        multisig_account: address, transaction_id: u64): bool acquires MultisigAccount {
        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
        let transaction = table::borrow(&mut multisig_account_resource.transactions, transaction_id);
        transaction_id == multisig_account_resource.last_transaction_id + 1 &&
            simple_map::length(&transaction.rejections) >= multisig_account_resource.signatures_required
    }

    #[view]
    public fun get_next_multisig_account_address(creator: address): address {
        let owner_nonce = account::get_sequence_number(creator);
        create_resource_address(&creator, create_multisig_account_seed(to_bytes(&owner_nonce)))
    }

    #[view]
    /// Return the id of the last transaction that was executed or removed.
    public fun last_resolved_transaction_id(multisig_account: address): u64 acquires MultisigAccount {
        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
        multisig_account_resource.last_transaction_id
    }

    /// Creates a new multisig account on top of an existing account.
    ///
    /// This offers a migration path for an existing account with a multi-ed25519 auth key (native multisig account).
    /// In order to ensure a malicious module cannot obtain backdoor control over an existing account, a signed message
    /// with a valid signature from the account's auth key is required.
    public entry fun create_with_existing_account(
        multisig_account: &signer,
        owners: vector<address>,
        signatures_required: u64,
        account_scheme: u8,
        account_public_key: vector<u8>,
        create_multisig_account_signed_message: vector<u8>,
    ) {
        // Verify that the `MultisigAccountCreationMessage` has the right information and is signed by the account
        // owner's key.
        let proof_challenge = MultisigAccountCreationMessage {
            chain_id: chain_id::get(),
        };
        account::verify_signed_message(
            address_of(multisig_account),
            account_scheme,
            account_public_key,
            create_multisig_account_signed_message,
            proof_challenge,
        );

        create_with_owners_internal(
            multisig_account,
            owners,
            signatures_required,
            option::none<SignerCapability>(),
        );
    }

    /// Creates a new multisig account and add the signer as a single owner.
    public entry fun create(owner: &signer, signatures_required: u64) {
        create_with_owners(owner, vector[], signatures_required);
    }

    /// Creates a new multisig account with the specified additional owner list and signatures required.
    ///
    /// @param additional_owners The owner account who calls this function cannot be in the additional_owners and there
    /// cannot be any duplicate owners in the list.
    /// @param signatures_require The number of signatures required to execute a transaction. Must be at least 1 and
    /// at most the total number of owners.
    public entry fun create_with_owners(owner: &signer, additional_owners: vector<address>, signatures_required: u64) {
        let (multisig_account, multisig_signer_cap) = create_multisig_account(owner);
        vector::push_back(&mut additional_owners, address_of(owner));
        create_with_owners_internal(
            &multisig_account,
            additional_owners,
            signatures_required,
            option::some(multisig_signer_cap),
        );
    }

    fun create_with_owners_internal(
        multisig_account: &signer,
        owners: vector<address>,
        signatures_required: u64,
        multisig_account_signer_cap: Option<SignerCapability>,
    ) {
        assert!(
            signatures_required > 0 && signatures_required <= vector::length(&owners),
            error::invalid_argument(EINVALID_SIGNATURES_REQUIRED),
        );

        validate_owners(&owners, address_of(multisig_account));
        move_to(multisig_account, MultisigAccount {
            owners,
            signatures_required,
            transactions: table::new<u64, MultisigTransaction>(),
            // First transaction will start at id 1 instead of 0.
            last_transaction_id: 0,
            next_transaction_id: 1,
            signer_cap: multisig_account_signer_cap,
            add_owners_events: new_event_handle<AddOwnersEvent>(multisig_account),
            remove_owners_events: new_event_handle<RemoveOwnersEvent>(multisig_account),
            update_signature_required_events: new_event_handle<UpdateSignaturesRequiredEvent>(multisig_account),
            create_transaction_events: new_event_handle<CreateTransactionEvent>(multisig_account),
            approve_transaction_events: new_event_handle<ApproveTransactionEvent>(multisig_account),
            reject_transaction_events: new_event_handle<RejectTransactionEvent>(multisig_account),
            execute_transaction_events: new_event_handle<ExecuteTransactionEvent>(multisig_account),
            remove_transaction_events: new_event_handle<RemoveTransactionEvent>(multisig_account),
        });
    }

    /// Add new owners to the multisig account. This can only be invoked by the multisig account itself, through the
    /// proposal flow.
    ///
    /// Note that this function is not public so it can only be invoked directly instead of via a module or script. This
    /// ensures that a multisig transaction cannot lead to another module obtaining the multisig signer and using it to
    /// maliciously alter the owners list.
    entry fun add_owners(multisig_account: &signer, new_owners: vector<address>) acquires MultisigAccount {
        // Short circuit if new owners list is empty.
        // This avoids emitting an event if no changes happen, which is confusing to off-chain components.
        if (vector::length(&new_owners) == 0) {
            return
        };

        let multisig_address = address_of(multisig_account);
        assert_multisig_account_exists(multisig_address);
        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_address);

        vector::append(&mut multisig_account_resource.owners, new_owners);
        validate_owners(&multisig_account_resource.owners, multisig_address);
        emit_event(&mut multisig_account_resource.add_owners_events, AddOwnersEvent {
            owners_added: new_owners,
        });
    }

    /// Remove owners from the multisig account. This can only be invoked by the multisig account itself, through the
    /// proposal flow.
    ///
    /// This function skips any owners who are not in the multisig account's list of owners.
    /// Note that this function is not public so it can only be invoked directly instead of via a module or script. This
    /// ensures that a multisig transaction cannot lead to another module obtaining the multisig signer and using it to
    /// maliciously alter the owners list.
    entry fun remove_owners(
        multisig_account: &signer, owners_to_remove: vector<address>) acquires MultisigAccount {
        // Short circuit if the list of owners to remove is empty.
        // This avoids emitting an event if no changes happen, which is confusing to off-chain components.
        if (vector::length(&owners_to_remove) == 0) {
            return
        };

        let multisig_address = address_of(multisig_account);
        assert_multisig_account_exists(multisig_address);
        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_address);

        let i = 0;
        let len = vector::length(&owners_to_remove);
        let owners = &mut multisig_account_resource.owners;
        let owners_removed = vector::empty<address>();
        while (i < len) {
            let owner_to_remove = *vector::borrow(&owners_to_remove, i);
            let (found, index) = vector::index_of(owners, &owner_to_remove);
            // Only remove an owner if they're present in the owners list.
            if (found) {
                vector::push_back(&mut owners_removed, owner_to_remove);
                vector::swap_remove(owners, index);
            };
            i = i + 1;
        };

        // Make sure there's still at least as many owners as the number of signatures required.
        // This also ensures that there's at least one owner left as signature threshold must be > 0.
        assert!(
            vector::length(owners) >= multisig_account_resource.signatures_required,
            error::invalid_state(ENOT_ENOUGH_OWNERS),
        );

        emit_event(&mut multisig_account_resource.remove_owners_events, RemoveOwnersEvent { owners_removed });
    }

    /// Update the number of signatures required to execute transaction in the specified multisig account.
    ///
    /// This can only be invoked by the multisig account itself, through the proposal flow.
    /// Note that this function is not public so it can only be invoked directly instead of via a module or script. This
    /// ensures that a multisig transaction cannot lead to another module obtaining the multisig signer and using it to
    /// maliciously alter the number of signatures required.
    entry fun update_signatures_required(
        multisig_account: &signer, new_signatures_required: u64) acquires MultisigAccount {
        let multisig_address = address_of(multisig_account);
        assert_multisig_account_exists(multisig_address);
        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_address);
        // Short-circuit if the new number of signatures required is the same as before.
        // This avoids emitting an event.
        if (multisig_account_resource.signatures_required == new_signatures_required) {
            return
        };
        let num_owners = vector::length(&multisig_account_resource.owners);
        assert!(
            new_signatures_required > 0 && new_signatures_required <= num_owners,
            error::invalid_argument(EINVALID_SIGNATURES_REQUIRED),
        );

        let old_signatures_required = multisig_account_resource.signatures_required;
        multisig_account_resource.signatures_required = new_signatures_required;
        emit_event(
            &mut multisig_account_resource.update_signature_required_events,
            UpdateSignaturesRequiredEvent {
                old_signatures_required,
                new_signatures_required,
            }
        );
    }

    /// Create a multisig transaction, which will have one approval initially (from the creator).
    ///
    /// @param target_function The target function to call such as 0x123::module_to_call::function_to_call.
    /// @param args Vector of BCS-encoded argument values to invoke the target function with.
    public entry fun create_transaction(
        owner: &signer,
        multisig_account: address,
        target_function: String,
        args: vector<u8>,
    ) acquires MultisigAccount {
        assert!(string::length(&target_function) > 0, error::invalid_argument(ETARGET_FUNCTION_CANNOT_BE_EMPTY));

        assert_multisig_account_exists(multisig_account);
        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
        assert_is_owner(owner, multisig_account_resource);

        let creator = address_of(owner);
        let transaction = MultisigTransaction {
            payload: option::some(TransactionPayload { target_function, args }),
            payload_hash: option::none<PayloadHash>(),
            approvals: simple_map::create<address, bool>(),
            rejections: simple_map::create<address, bool>(),
            creator,
            metadata: simple_map::create<String, vector<u8>>(),
        };
        add_transaction(creator, multisig_account_resource, transaction);
    }

    /// Create a multisig transaction with a transaction hash instead of the full payload.
    /// This means the payload will be stored off chain for gas saving. Later, during execution, the executor will need
    /// to provide the full payload, which will be validated against the hash stored on-chain.
    ///
    /// @param function_hash The sha-256 hash of the function to invoke, e.g. 0x123::module_to_call::function_to_call.
    /// @param args_hash The sha-256 hash of the function arguments - a concatenated vector of the bcs-encoded
    /// function arguments.
    public entry fun create_transaction_with_hash(
        owner: &signer,
        multisig_account: address,
        function_hash: vector<u8>,
        args_hash: vector<u8>,
    ) acquires MultisigAccount {
        // These are sha3-256 hashes so they must be exactly 32 bytes.
        assert!(vector::length(&function_hash) == 32, error::invalid_argument(EINVALID_FUNCTION_HASH));
        assert!(vector::length(&args_hash) == 32, error::invalid_argument(EINVALID_FUNCTION_ARGS_HASH));

        assert_multisig_account_exists(multisig_account);
        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
        assert_is_owner(owner, multisig_account_resource);

        let creator = address_of(owner);
        let transaction = MultisigTransaction {
            payload: option::none<TransactionPayload>(),
            payload_hash: option::some(PayloadHash { function_hash, args_hash }),
            approvals: simple_map::create<address, bool>(),
            rejections: simple_map::create<address, bool>(),
            creator,
            metadata: simple_map::create<String, vector<u8>>(),
        };
        add_transaction(creator, multisig_account_resource, transaction);
    }

    /// Approve a multisig transaction.
    public entry fun approve_transaction(
        owner: &signer, multisig_account: address, transaction_id: u64) acquires MultisigAccount {
        vote_transanction(owner, multisig_account, transaction_id, true);
    }

    /// Reject a multisig transaction.
    public entry fun reject_transaction(
        owner: &signer, multisig_account: address, transaction_id: u64) acquires MultisigAccount {
        vote_transanction(owner, multisig_account, transaction_id, false);
    }

    /// Generic function that can be used to either approve or reject a multisig transaction
    public entry fun vote_transanction(
        owner: &signer, multisig_account: address, transaction_id: u64, approved: bool) acquires MultisigAccount {
        assert_multisig_account_exists(multisig_account);
        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
        assert_is_owner(owner, multisig_account_resource);

        assert!(
            table::contains(&multisig_account_resource.transactions, transaction_id),
            error::not_found(ETRANSACTION_NOT_FOUND),
        );
        let transaction = table::borrow_mut(&mut multisig_account_resource.transactions, transaction_id);
        let owner_addr = address_of(owner);
        if (approved) {
            assert!(
                !simple_map::contains_key(&transaction.approvals, &owner_addr),
                error::already_exists(TRANSACTION_HAS_ALREADY_BEEN_APPROVED)
            );
            simple_map::add(&mut transaction.approvals, owner_addr, true);
            // Revoke rejection.
            if (simple_map::contains_key(&mut transaction.rejections, &owner_addr)) {
                simple_map::remove(&mut transaction.rejections, &owner_addr);
            };
            emit_event(
                &mut multisig_account_resource.approve_transaction_events,
                ApproveTransactionEvent {
                    owner: owner_addr,
                    transaction_id,
                    num_approvals: simple_map::length(&transaction.approvals),
                }
            );
        } else {
            assert!(
                !simple_map::contains_key(&transaction.rejections, &owner_addr),
                error::already_exists(TRANSACTION_HAS_ALREADY_BEEN_REJECTED)
            );
            simple_map::add(&mut transaction.rejections, owner_addr, true);
            // Revoke approval.
            if (simple_map::contains_key(&mut transaction.approvals, &owner_addr)) {
                simple_map::remove(&mut transaction.approvals, &owner_addr);
            };
            emit_event(
                &mut multisig_account_resource.reject_transaction_events,
                RejectTransactionEvent {
                    owner: owner_addr,
                    transaction_id,
                    num_rejections: simple_map::length(&transaction.rejections),
                }
            );
        };
    }

    /// Remove the next transaction if it has sufficient owner rejections.
    public entry fun remove_transaction(
        owner: &signer,
        multisig_account: address,
    ) acquires MultisigAccount {
        assert_multisig_account_exists(multisig_account);
        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
        assert_is_owner(owner, multisig_account_resource);
        let transaction_id = multisig_account_resource.last_transaction_id + 1;
        assert!(
            table::contains(&multisig_account_resource.transactions, transaction_id),
            error::not_found(ETRANSACTION_NOT_FOUND),
        );
        let transaction = table::remove(&mut multisig_account_resource.transactions, transaction_id);
        assert!(
            simple_map::length(&transaction.rejections) >= multisig_account_resource.signatures_required,
            error::invalid_state(ENOT_ENOUGH_REJECTIONS),
        );

        multisig_account_resource.last_transaction_id = transaction_id;
        emit_event(
            &mut multisig_account_resource.remove_transaction_events,
            RemoveTransactionEvent {
                transaction_id,
                num_rejections: simple_map::length(&transaction.rejections),
                executor: address_of(owner),
            }
        );
    }

    /// Execute the next transaction if it has enought approvals. This doesn't actually invoke the target function but
    /// simply marks the transaction as already been executed (by removing it from the transactions table). Actual
    /// function invocation is done as part executing the MultisigTransaction.
    ///
    /// This function is private so no other code can call this beside the VM itself as part of MultisigTransaction.
    ///
    /// @param target_function Optional and can be empty if the full transaction payload is stored on chain.
    /// @param args Optional and can be empty if the full transaction payload is stored on chain.
    /// @return The transaction payload to execute as the multisig account.
    fun execute_transaction(
        owner: &signer,
        multisig_account: address,
        target_function: String,
        args: vector<u8>,
    ): TransactionPayload acquires MultisigAccount {
        assert_multisig_account_exists(multisig_account);
        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
        assert_is_owner(owner, multisig_account_resource);
        let transaction_id = multisig_account_resource.last_transaction_id + 1;
        assert!(
            table::contains(&multisig_account_resource.transactions, transaction_id),
            error::not_found(ETRANSACTION_NOT_FOUND),
        );
        let transaction = table::remove(&mut multisig_account_resource.transactions, transaction_id);
        assert!(
            simple_map::length(&transaction.approvals) >= multisig_account_resource.signatures_required,
            error::invalid_state(ENOT_ENOUGH_APPROVALS),
        );

        let transaction_payload =
            if (option::is_some(&transaction.payload)) {
                option::extract(&mut transaction.payload)
            } else {
                let payload_hash = option::extract(&mut transaction.payload_hash);
                assert!(
                    sha3_256(*string::bytes(&target_function)) == payload_hash.function_hash,
                    error::invalid_argument(ETARGET_FUNCTION_DOES_NOT_MATCH_HASH),
                );
                assert!(
                    sha3_256(args) == payload_hash.args_hash,
                    error::invalid_argument(EARGUMENTS_DOES_NOT_MATCH_HASH),
                );
                TransactionPayload { target_function, args }
            };
        multisig_account_resource.last_transaction_id = transaction_id;
        emit_event(
            &mut multisig_account_resource.execute_transaction_events,
            ExecuteTransactionEvent {
                transaction_id,
                transaction_payload,
                num_approvals: simple_map::length(&transaction.approvals),
                executor: address_of(owner),
            }
        );

        transaction_payload
    }

    fun add_transaction(creator: address, multisig_account: &mut MultisigAccount, transaction: MultisigTransaction) {
        simple_map::add(&mut transaction.approvals, creator, true);

        let transaction_id = multisig_account.next_transaction_id;
        multisig_account.next_transaction_id = transaction_id + 1;
        table::add(&mut multisig_account.transactions, transaction_id, transaction);
        emit_event(
            &mut multisig_account.create_transaction_events,
            CreateTransactionEvent { transaction_id, transaction },
        );
    }

    fun create_multisig_account(owner: &signer): (signer, SignerCapability) {
        let owner_nonce = account::get_sequence_number(address_of(owner));
        let (multisig_signer, multisig_signer_cap) =
            account::create_resource_account(owner, create_multisig_account_seed(to_bytes(&owner_nonce)));
        // Register the account to receive APT as this is not done by default as part of the resource account creation
        // flow.
        if (!coin::is_account_registered<AptosCoin>(address_of(&multisig_signer))) {
            coin::register<AptosCoin>(&multisig_signer);
        };

        (multisig_signer, multisig_signer_cap)
    }

    fun create_multisig_account_seed(seed: vector<u8>): vector<u8> {
        // Generate a seed that will be used to create the resource account that hosts the staking contract.
        let multisig_account_seed = vector::empty<u8>();
        vector::append(&mut multisig_account_seed, DOMAIN_SEPARATOR);
        vector::append(&mut multisig_account_seed, seed);

        multisig_account_seed
    }

    fun validate_owners(owners: &vector<address>, multisig_account: address) {
        let distinct_owners = simple_map::create<address, bool>();
        let i = 0;
        let len = vector::length(owners);
        while (i < len) {
            let owner = *vector::borrow(owners, i);
            assert!(owner != multisig_account, error::invalid_argument(EOWNER_CANNOT_BE_MULTISIG_ACCOUNT_ITSELF));
            assert!(
                !simple_map::contains_key(&distinct_owners, &owner),
                error::invalid_argument(EDUPLICATE_OWNER),
            );
            simple_map::add(&mut distinct_owners, owner, true);
            i = i + 1;
        }
    }

    fun assert_is_owner(owner: &signer, multisig_account: &MultisigAccount) {
        assert!(
            vector::contains(&multisig_account.owners, &address_of(owner)),
            error::permission_denied(ENOT_OWNER),
        );
    }

    fun assert_multisig_account_exists(multisig_account: address) {
        assert!(exists<MultisigAccount>(multisig_account), error::invalid_state(EACCOUNT_NOT_MULTISIG));
    }

    #[test_only]
    use std::string::utf8;
    #[test_only]
    use aptos_framework::account::create_signer_for_test;
    #[test_only]
    use aptos_framework::aptos_account::create_account;
    use aptos_framework::chain_id;

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    public entry fun test_end_to_end(owner_1: &signer, owner_2: &signer, owner_3: &signer) acquires MultisigAccount {
        let owner_1_addr = address_of(owner_1);
        let owner_2_addr = address_of(owner_2);
        let owner_3_addr = address_of(owner_3);
        create_account(owner_1_addr);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        create_with_owners(owner_1, vector[owner_2_addr, owner_3_addr], 2);

        // Create three transactions.
        create_transaction(owner_1, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        create_transaction(owner_2, multisig_account, utf8(b"0x1::coin::deposit"), vector[1, 2, 3]);
        create_transaction_with_hash(owner_3, multisig_account, sha3_256(b"1"), sha3_256(vector[]));

        // Owner 3 doesn't need to explicitly approve as they created the transaction.
        approve_transaction(owner_1, multisig_account, 3);
        // Third transaction has 2 approvals but cannot be executed out-of-order.
        assert!(!can_be_executed(multisig_account, 3), 0);

        // Owner 1 doesn't need to explicitly approve as they created the transaction.
        approve_transaction(owner_2, multisig_account, 1);
        // First transaction has 2 approvals so it can be executed.
        assert!(can_be_executed(multisig_account, 1), 1);
        execute_transaction(owner_2, multisig_account,utf8(b""), vector[]);

        reject_transaction(owner_1, multisig_account, 2);
        reject_transaction(owner_3, multisig_account, 2);
        // Second transaction has 1 approval (owner 3) and 2 rejections (owners 1 & 2) and thus can be removed.
        assert!(can_be_removed(multisig_account, 2), 2);
        remove_transaction(owner_1, multisig_account);

        // Third transaction can be executed now.
        execute_transaction(owner_3, multisig_account, utf8(b"1"), vector[]);
    }

    #[test(owner = @0x123)]
    public entry fun test_create_with_single_owner(owner: &signer) acquires MultisigAccount {
        let owner_addr = address_of(owner);
        create_account(owner_addr);
        create(owner, 1);
        let multisig_account = get_next_multisig_account_address(owner_addr);
        assert_multisig_account_exists(multisig_account);
        assert!(owners(multisig_account) == vector[owner_addr], 0);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    public entry fun test_create_with_as_many_sigs_required_as_num_owners(
        owner_1: &signer, owner_2: &signer, owner_3: &signer) {
        let owner_1_addr = address_of(owner_1);
        create_account(owner_1_addr);
        create_with_owners(owner_1, vector[address_of(owner_2), address_of(owner_3)], 3);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        assert_multisig_account_exists(multisig_account);
    }

    #[test(owner = @0x123)]
    #[expected_failure(abort_code = 0x1000d, location = Self)]
    public entry fun test_create_with_zero_signatures_required_should_fail(owner: &signer) {
        create_account(address_of(owner));
        create(owner, 0);
    }

    #[test(owner = @0x123)]
    #[expected_failure(abort_code = 0x1000d, location = Self)]
    public entry fun test_create_with_too_many_signatures_required_should_fail(owner: &signer) {
        create_account(address_of(owner));
        create(owner, 2);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    public entry fun test_create_with_duplicate_owners_should_fail(
        owner_1: &signer, owner_2: &signer, owner_3: &signer) {
        create_account(address_of(owner_1));
        create_with_owners(owner_1, vector[
            // Duplicate owner 2 addresses.
            address_of(owner_2),
            address_of(owner_3),
            address_of(owner_2),
        ], 2);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    public entry fun test_create_with_creator_in_additional_owners_list_should_fail(
        owner_1: &signer, owner_2: &signer, owner_3: &signer) {
        create_account(address_of(owner_1));
        create_with_owners(owner_1, vector[
            // Duplicate owner 1 addresses.
            address_of(owner_1),
            address_of(owner_2),
            address_of(owner_3),
        ], 2);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    public entry fun test_update_signatures_required(
        owner_1: &signer, owner_2: &signer, owner_3: &signer) acquires MultisigAccount {
        let owner_1_addr = address_of(owner_1);
        create_account(owner_1_addr);
        create_with_owners(owner_1, vector[address_of(owner_2), address_of(owner_3)], 1);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        assert!(signatures_required(multisig_account) == 1, 0);
        update_signatures_required(&create_signer_for_test(multisig_account), 2);
        assert!(signatures_required(multisig_account) == 2, 1);
        // As many signatures required as number of owners (3).
        update_signatures_required(&create_signer_for_test(multisig_account), 3);
        assert!(signatures_required(multisig_account) == 3, 2);
    }

    #[test(owner = @0x123)]
    #[expected_failure(abort_code = 0x1000d, location = Self)]
    public entry fun test_update_with_zero_signatures_required_should_fail(owner:& signer) acquires MultisigAccount {
        create_account(address_of(owner));
        create(owner,1);
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        update_signatures_required(&create_signer_for_test(multisig_account), 0);
    }

    #[test(owner = @0x123)]
    #[expected_failure(abort_code = 0x1000d, location = Self)]
    public entry fun test_update_with_too_many_signatures_required_should_fail(
        owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        create(owner,1);
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        update_signatures_required(&create_signer_for_test(multisig_account), 2);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    public entry fun test_add_owners(owner_1: &signer, owner_2: &signer, owner_3: &signer) acquires MultisigAccount {
        create_account(address_of(owner_1));
        create(owner_1, 1);
        let owner_1_addr = address_of(owner_1);
        let owner_2_addr = address_of(owner_2);
        let owner_3_addr = address_of(owner_3);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        let multisig_signer = &create_signer_for_test(multisig_account);
        assert!(owners(multisig_account) == vector[owner_1_addr], 0);
        // Adding an empty vector of new owners should be no-op.
        add_owners(multisig_signer, vector[]);
        assert!(owners(multisig_account) == vector[owner_1_addr], 1);
        add_owners(multisig_signer, vector[owner_2_addr, owner_3_addr]);
        assert!(owners(multisig_account) == vector[owner_1_addr, owner_2_addr, owner_3_addr], 2);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    public entry fun test_remove_owners(owner_1: &signer, owner_2: &signer, owner_3: &signer) acquires MultisigAccount {
        let owner_1_addr = address_of(owner_1);
        let owner_2_addr = address_of(owner_2);
        let owner_3_addr = address_of(owner_3);
        create_account(owner_1_addr);
        create_with_owners(owner_1, vector[owner_2_addr, owner_3_addr], 1);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        let multisig_signer = &create_signer_for_test(multisig_account);
        assert!(owners(multisig_account) == vector[owner_2_addr, owner_3_addr, owner_1_addr], 0);
        // Removing an empty vector of owners should be no-op.
        remove_owners(multisig_signer, vector[]);
        assert!(owners(multisig_account) == vector[owner_2_addr, owner_3_addr, owner_1_addr], 1);
        remove_owners(multisig_signer, vector[owner_2_addr]);
        assert!(owners(multisig_account) == vector[owner_1_addr, owner_3_addr], 2);
        // Removing owners that don't exist should be no-op.
        remove_owners(multisig_signer, vector[@0x130]);
        assert!(owners(multisig_account) == vector[owner_1_addr, owner_3_addr], 3);
        // Removing with duplicate owners should still work.
        remove_owners(multisig_signer, vector[owner_3_addr, owner_3_addr, owner_3_addr]);
        assert!(owners(multisig_account) == vector[owner_1_addr], 4);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    #[expected_failure(abort_code = 0x30005, location = Self)]
    public entry fun test_remove_all_owners_should_fail(
        owner_1: &signer, owner_2: &signer, owner_3: &signer) acquires MultisigAccount {
        let owner_1_addr = address_of(owner_1);
        let owner_2_addr = address_of(owner_2);
        let owner_3_addr = address_of(owner_3);
        create_account(owner_1_addr);
        create_with_owners(owner_1, vector[owner_2_addr, owner_3_addr], 1);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        assert!(owners(multisig_account) == vector[owner_2_addr, owner_3_addr, owner_1_addr], 0);
        let multisig_signer = &create_signer_for_test(multisig_account);
        remove_owners(multisig_signer, vector[owner_1_addr, owner_2_addr, owner_3_addr]);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    #[expected_failure(abort_code = 0x30005, location = Self)]
    public entry fun test_remove_owners_with_fewer_remaining_than_signature_threshold_should_fail(
        owner_1: &signer, owner_2: &signer, owner_3: &signer) acquires MultisigAccount {
        let owner_1_addr = address_of(owner_1);
        let owner_2_addr = address_of(owner_2);
        let owner_3_addr = address_of(owner_3);
        create_account(owner_1_addr);
        create_with_owners(owner_1, vector[owner_2_addr, owner_3_addr], 2);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        let multisig_signer = &create_signer_for_test(multisig_account);
        // Remove 2 owners so there's one left, which is less than the signature threshold of 2.
        remove_owners(multisig_signer, vector[owner_2_addr, owner_3_addr]);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    public entry fun test_create_transaction(
        owner_1: &signer, owner_2: &signer, owner_3: &signer) acquires MultisigAccount {
        let owner_1_addr = address_of(owner_1);
        let owner_2_addr = address_of(owner_2);
        let owner_3_addr = address_of(owner_3);
        create_account(owner_1_addr);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        create_with_owners(owner_1, vector[owner_2_addr, owner_3_addr], 2);

        create_transaction(owner_1, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        let transaction = get_transaction(multisig_account, 1);
        assert!(transaction.creator == owner_1_addr, 0);
        assert!(option::is_some(&transaction.payload), 1);
        assert!(option::is_none(&transaction.payload_hash), 2);
        let payload = option::extract(&mut transaction.payload);
        assert!(payload.target_function == utf8(b"0x1::coin::transfer"), 3);
        assert!(payload.args == vector[1, 2, 3], 4);
        assert!(simple_map::length(&transaction.approvals) == 1, 5);
        assert!(simple_map::length(&transaction.rejections) == 0, 5);
    }

    #[test(owner = @0x123)]
    #[expected_failure(abort_code = 0x10004, location = Self)]
    public entry fun test_create_transaction_with_empty_target_function_should_fail(
        owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        create(owner,1);
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        create_transaction(owner, multisig_account, utf8(b""), vector[1, 2, 3]);
    }

    #[test(owner = @0x123, non_owner = @0x124)]
    #[expected_failure(abort_code = 0x50003, location = Self)]
    public entry fun test_create_transaction_with_non_owner_should_fail(
        owner: &signer, non_owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        create(owner,1);
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        create_transaction(non_owner, multisig_account, utf8(b"test"), vector[]);
    }

    #[test(owner = @0x123)]
    public entry fun test_create_transaction_with_hashes(owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        create(owner,1);
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        create_transaction_with_hash(owner, multisig_account, sha3_256(b"1"), sha3_256(vector[]));
    }

    #[test(owner = @0x123)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    public entry fun test_create_transaction_with_empty_function_hash_should_fail(
        owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        create(owner,1);
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        create_transaction_with_hash(owner, multisig_account, b"", sha3_256(vector[]));
    }

    #[test(owner = @0x123)]
    #[expected_failure(abort_code = 0x1000e, location = Self)]
    public entry fun test_create_transaction_with_empty_args_hash_should_fail(
        owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        create(owner,1);
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        create_transaction_with_hash(owner, multisig_account, sha3_256(b"1"), vector[]);
    }

    #[test(owner = @0x123, non_owner = @0x124)]
    #[expected_failure(abort_code = 0x50003, location = Self)]
    public entry fun test_create_transaction_with_hashes_and_non_owner_should_fail(
        owner: &signer, non_owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        create(owner,1);
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        create_transaction_with_hash(non_owner, multisig_account, sha3_256(b"1"), sha3_256(vector[]));
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    public entry fun test_approve_transaction(
        owner_1: &signer, owner_2: &signer, owner_3: &signer) acquires MultisigAccount {
        let owner_1_addr = address_of(owner_1);
        let owner_2_addr = address_of(owner_2);
        let owner_3_addr = address_of(owner_3);
        create_account(owner_1_addr);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        create_with_owners(owner_1, vector[owner_2_addr, owner_3_addr], 2);

        create_transaction(owner_1, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        approve_transaction(owner_2, multisig_account, 1);
        approve_transaction(owner_3, multisig_account, 1);
        let transaction = get_transaction(multisig_account, 1);
        assert!(simple_map::length(&transaction.approvals) == 3, 0);
        assert!(*simple_map::borrow(&transaction.approvals, &owner_1_addr), 1);
        assert!(*simple_map::borrow(&transaction.approvals, &owner_2_addr), 2);
        assert!(*simple_map::borrow(&transaction.approvals, &owner_3_addr), 3);
    }

    #[test(owner = @0x123)]
    #[expected_failure(abort_code = 0x60007, location = Self)]
    public entry fun test_approve_transaction_with_invalid_transaction_id_should_fail(
        owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        create(owner, 1);
        // Transaction is created with id 1.
        create_transaction(owner, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        approve_transaction(owner, multisig_account, 2);
    }

    #[test(owner = @0x123, non_owner = @0x124)]
    #[expected_failure(abort_code = 0x50003, location = Self)]
    public entry fun test_approve_transaction_with_non_owner_should_fail(
        owner: &signer, non_owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        create(owner, 1);
        // Transaction is created with id 1.
        create_transaction(owner, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        approve_transaction(non_owner, multisig_account, 1);
    }

    #[test(owner = @0x123)]
    public entry fun test_approval_transaction_should_revoke_rejection(owner: &signer) acquires MultisigAccount {
        let owner_addr = address_of(owner);
        create_account(owner_addr);
        let multisig_account = get_next_multisig_account_address(owner_addr);
        create(owner, 1);

        create_transaction(owner, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        reject_transaction(owner, multisig_account, 1);
        assert!(simple_map::length(&get_transaction(multisig_account, 1).rejections) == 1, 0);
        approve_transaction(owner, multisig_account, 1);
        let transaction = get_transaction(multisig_account, 1);
        assert!(simple_map::length(&transaction.approvals) == 1, 1);
        // Owner's original rejection has been revoked.
        assert!(simple_map::length(&transaction.rejections) == 0, 2);
    }

    #[test(owner = @0x123)]
    #[expected_failure(abort_code = 0x80010, location = Self)]
    public entry fun test_approve_transaction_twice_should_fail(
        owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        create(owner, 1);
        create_transaction(owner, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        approve_transaction(owner, multisig_account, 1);
        approve_transaction(owner, multisig_account, 1);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    public entry fun test_reject_transaction(
        owner_1: &signer, owner_2: &signer, owner_3: &signer) acquires MultisigAccount {
        let owner_1_addr = address_of(owner_1);
        let owner_2_addr = address_of(owner_2);
        let owner_3_addr = address_of(owner_3);
        create_account(owner_1_addr);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        create_with_owners(owner_1, vector[owner_2_addr, owner_3_addr], 2);

        create_transaction(owner_1, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        reject_transaction(owner_1, multisig_account, 1);
        reject_transaction(owner_2, multisig_account, 1);
        reject_transaction(owner_3, multisig_account, 1);
        let transaction = get_transaction(multisig_account, 1);
        assert!(simple_map::length(&transaction.rejections) == 3, 0);
        assert!(*simple_map::borrow(&transaction.rejections, &owner_1_addr), 1);
        assert!(*simple_map::borrow(&transaction.rejections, &owner_2_addr), 2);
        assert!(*simple_map::borrow(&transaction.rejections, &owner_3_addr), 3);
    }

    #[test(owner = @0x123)]
    public entry fun test_reject_transaction_should_revoke_approval(owner: &signer) acquires MultisigAccount {
        let owner_addr = address_of(owner);
        create_account(owner_addr);
        let multisig_account = get_next_multisig_account_address(owner_addr);
        create(owner, 1);

        create_transaction(owner, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        assert!(simple_map::length(&get_transaction(multisig_account, 1).approvals) == 1, 0);
        reject_transaction(owner, multisig_account, 1);
        let transaction = get_transaction(multisig_account, 1);
        assert!(simple_map::length(&transaction.rejections) == 1, 1);
        // Owner's original approval has been revoked.
        assert!(simple_map::length(&transaction.approvals) == 0, 2);
    }

    #[test(owner = @0x123)]
    #[expected_failure(abort_code = 0x60007, location = Self)]
    public entry fun test_reject_transaction_with_invalid_transaction_id_should_fail(
        owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        create(owner, 1);
        // Transaction is created with id 1.
        create_transaction(owner, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        reject_transaction(owner, multisig_account, 2);
    }

    #[test(owner = @0x123, non_owner = @0x124)]
    #[expected_failure(abort_code = 0x50003, location = Self)]
    public entry fun test_reject_transaction_with_non_owner_should_fail(
        owner: &signer, non_owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        create(owner, 1);
        reject_transaction(non_owner, multisig_account, 1);
    }

    #[test(owner = @0x123)]
    #[expected_failure(abort_code = 0x80011, location = Self)]
    public entry fun test_reject_transaction_twice_should_fail(
        owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        create(owner, 1);
        create_transaction(owner, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        reject_transaction(owner, multisig_account, 1);
        reject_transaction(owner, multisig_account, 1);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    public entry fun test_execute_transaction(
        owner_1: &signer, owner_2: &signer, owner_3: &signer) acquires MultisigAccount {
        let owner_1_addr = address_of(owner_1);
        let owner_2_addr = address_of(owner_2);
        let owner_3_addr = address_of(owner_3);
        create_account(owner_1_addr);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        create_with_owners(owner_1, vector[owner_2_addr, owner_3_addr], 2);

        create_transaction(owner_1, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        // Owner 1 doesn't need to explicitly approve as they created the transaction.
        approve_transaction(owner_2, multisig_account, 1);
        assert!(can_be_executed(multisig_account, 1), 1);
        assert!(table::contains(&borrow_global<MultisigAccount>(multisig_account).transactions, 1), 0);
        execute_transaction(owner_3, multisig_account,utf8(b""), vector[]);
        assert!(!table::contains(&borrow_global<MultisigAccount>(multisig_account).transactions, 1), 1);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    public entry fun test_execute_transaction_with_full_payload(
        owner_1: &signer, owner_2: &signer, owner_3: &signer) acquires MultisigAccount {
        let owner_1_addr = address_of(owner_1);
        let owner_2_addr = address_of(owner_2);
        let owner_3_addr = address_of(owner_3);
        create_account(owner_1_addr);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        create_with_owners(owner_1, vector[owner_2_addr, owner_3_addr], 2);

        create_transaction_with_hash(owner_3, multisig_account, sha3_256(b"1"), sha3_256(vector[]));
        // Owner 3 doesn't need to explicitly approve as they created the transaction.
        approve_transaction(owner_1, multisig_account, 1);
        assert!(can_be_executed(multisig_account, 1), 1);
        assert!(table::contains(&borrow_global<MultisigAccount>(multisig_account).transactions, 1), 0);
        execute_transaction(owner_3, multisig_account,utf8(b"1"), vector[]);
        assert!(!table::contains(&borrow_global<MultisigAccount>(multisig_account).transactions, 1), 1);
    }

    #[test(owner = @0x123, non_owner = @0x124)]
    #[expected_failure(abort_code = 0x50003, location = Self)]
    public entry fun test_execute_transaction_with_non_owner_should_fail(
        owner: &signer, non_owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        create(owner,1);

        create_transaction(owner, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        assert!(can_be_executed(multisig_account, 1), 1);
        execute_transaction(non_owner, multisig_account,utf8(b""), vector[]);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    #[expected_failure(abort_code = 0x3000B, location = Self)]
    public entry fun test_execute_transaction_without_sufficient_approvals_should_fail(
        owner_1: &signer, owner_2: &signer, owner_3: &signer) acquires MultisigAccount {
        let owner_1_addr = address_of(owner_1);
        let owner_2_addr = address_of(owner_2);
        let owner_3_addr = address_of(owner_3);
        create_account(owner_1_addr);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        create_with_owners(owner_1, vector[owner_2_addr, owner_3_addr], 2);

        create_transaction_with_hash(owner_3, multisig_account, sha3_256(b"1"), sha3_256(vector[]));
        execute_transaction(owner_3, multisig_account, utf8(b"1"), vector[]);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    public entry fun test_remove_transaction(
        owner_1: &signer, owner_2: &signer, owner_3: &signer) acquires MultisigAccount {
        let owner_1_addr = address_of(owner_1);
        let owner_2_addr = address_of(owner_2);
        let owner_3_addr = address_of(owner_3);
        create_account(owner_1_addr);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        create_with_owners(owner_1, vector[owner_2_addr, owner_3_addr], 2);

        create_transaction(owner_1, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        reject_transaction(owner_2, multisig_account, 1);
        reject_transaction(owner_3, multisig_account, 1);
        assert!(can_be_removed(multisig_account, 1), 1);
        assert!(table::contains(&borrow_global<MultisigAccount>(multisig_account).transactions, 1), 0);
        remove_transaction(owner_3, multisig_account);
        assert!(!table::contains(&borrow_global<MultisigAccount>(multisig_account).transactions, 1), 1);
    }

    #[test(owner = @0x123, non_owner = @0x124)]
    #[expected_failure(abort_code = 0x50003, location = Self)]
    public entry fun test_remove_transaction_with_non_owner_should_fail(
        owner: &signer, non_owner: &signer) acquires MultisigAccount {
        create_account(address_of(owner));
        let multisig_account = get_next_multisig_account_address(address_of(owner));
        create(owner,1);

        create_transaction(owner, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        reject_transaction(owner, multisig_account, 1);
        remove_transaction(non_owner, multisig_account);
    }

    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    #[expected_failure(abort_code = 0x3000c, location = Self)]
    public entry fun test_remove_transaction_without_sufficient_rejections_should_fail(owner_1: &signer, owner_2: &signer, owner_3: &signer) acquires MultisigAccount {
        let owner_1_addr = address_of(owner_1);
        let owner_2_addr = address_of(owner_2);
        let owner_3_addr = address_of(owner_3);
        create_account(owner_1_addr);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        create_with_owners(owner_1, vector[owner_2_addr, owner_3_addr], 2);

        create_transaction(owner_1, multisig_account, utf8(b"0x1::coin::transfer"), vector[1, 2, 3]);
        reject_transaction(owner_2, multisig_account, 1);
        remove_transaction(owner_3, multisig_account);
    }
}
