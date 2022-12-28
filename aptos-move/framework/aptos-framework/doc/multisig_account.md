
<a name="0x1_multisig_account"></a>

# Module `0x1::multisig_account`

Enhanced multisig account standard on Aptos. This is different from the native multisig scheme support enforced via
the account's auth key.

This module allows creating a flexible and powerful multisig account with seamless support for updating owners
without changing the auth key. Users can choose to store transaction payloads waiting for owner signatures on chain
or off chain (primary consideration is decentralization/transparency vs gas cost).

The multisig account is a resource account underneath. By default, it has no auth key and can only be controlled via
the special multisig transaction flow. However, owners can create a transaction to change the auth key to match a
private key off chain if so desired.

Transactions need to be executed in order of creation, similar to transactions for a normal Aptos account (enforced
with acount nonce).

The flow is like below:
1. Owners can create a new multisig account by calling create (signer is default single owner) or with
create_with_owners where multiple initial owner addresses can be specified. This is different (and easier) from
the native multisig scheme where the owners' public keys have to be specified. Here, only addresses are needed.
2. Owners can be added/removed any time by calling add_owners or remove_owners. The transactions to do still need
to follow the k-of-n scheme specified for the multisig account.
3. To create a new transaction, an owner can call create_transaction with the transaction payload: specified module
(address + name), the name of the function to call, and argument values. This will store the full transaction
payload on chain, which adds decentralization (censorship is not possible) and makes it easier to fetch all
transactions waiting for execution. If saving gas is desired, an owner can alternatively call
create_transaction_with_hash where only the payload hash is stored (module + function + args). Later execution will
be verified using the hash. Only owners can create transactions and a transaction id (incremeting id) will be
assigned.
4. To approve or reject a transaction, other owners can call approve() or reject() with the transaction id.
5. If there are enough approvals, any owner can execute the transaction using the special MultisigTransaction type
with the transaction id if the full payload is already stored on chain or with the transaction payload if only a
hash is stored. Transaction execution will first check with this module that the transaction payload has gotten
enough signatures. If so, it will be executed as the multisig account. The owner who executes will pay for gas.
6. If there are enough rejections, any owner can remove the transaction by calling remove().


-  [Resource `MultisigAccount`](#0x1_multisig_account_MultisigAccount)
-  [Struct `MultisigTransaction`](#0x1_multisig_account_MultisigTransaction)
-  [Struct `TransactionPayload`](#0x1_multisig_account_TransactionPayload)
-  [Struct `PayloadHash`](#0x1_multisig_account_PayloadHash)
-  [Struct `MultisigAccountCreationMessage`](#0x1_multisig_account_MultisigAccountCreationMessage)
-  [Struct `AddOwnersEvent`](#0x1_multisig_account_AddOwnersEvent)
-  [Struct `RemoveOwnersEvent`](#0x1_multisig_account_RemoveOwnersEvent)
-  [Struct `UpdateSignaturesRequiredEvent`](#0x1_multisig_account_UpdateSignaturesRequiredEvent)
-  [Struct `CreateTransactionEvent`](#0x1_multisig_account_CreateTransactionEvent)
-  [Struct `ApproveTransactionEvent`](#0x1_multisig_account_ApproveTransactionEvent)
-  [Struct `RejectTransactionEvent`](#0x1_multisig_account_RejectTransactionEvent)
-  [Struct `RemoveTransactionEvent`](#0x1_multisig_account_RemoveTransactionEvent)
-  [Struct `ExecuteTransactionEvent`](#0x1_multisig_account_ExecuteTransactionEvent)
-  [Constants](#@Constants_0)
-  [Function `signatures_required`](#0x1_multisig_account_signatures_required)
-  [Function `owners`](#0x1_multisig_account_owners)
-  [Function `get_transaction`](#0x1_multisig_account_get_transaction)
-  [Function `can_be_executed`](#0x1_multisig_account_can_be_executed)
-  [Function `can_be_removed`](#0x1_multisig_account_can_be_removed)
-  [Function `get_next_multisig_account_address`](#0x1_multisig_account_get_next_multisig_account_address)
-  [Function `last_resolved_transaction_id`](#0x1_multisig_account_last_resolved_transaction_id)
-  [Function `create_with_existing_account`](#0x1_multisig_account_create_with_existing_account)
-  [Function `create`](#0x1_multisig_account_create)
-  [Function `create_with_owners`](#0x1_multisig_account_create_with_owners)
-  [Function `create_with_owners_internal`](#0x1_multisig_account_create_with_owners_internal)
-  [Function `add_owners`](#0x1_multisig_account_add_owners)
-  [Function `remove_owners`](#0x1_multisig_account_remove_owners)
-  [Function `update_signatures_required`](#0x1_multisig_account_update_signatures_required)
-  [Function `create_transaction`](#0x1_multisig_account_create_transaction)
-  [Function `create_transaction_with_hash`](#0x1_multisig_account_create_transaction_with_hash)
-  [Function `approve_transaction`](#0x1_multisig_account_approve_transaction)
-  [Function `reject_transaction`](#0x1_multisig_account_reject_transaction)
-  [Function `vote_transanction`](#0x1_multisig_account_vote_transanction)
-  [Function `remove_transaction`](#0x1_multisig_account_remove_transaction)
-  [Function `execute_transaction`](#0x1_multisig_account_execute_transaction)
-  [Function `add_transaction`](#0x1_multisig_account_add_transaction)
-  [Function `create_multisig_account`](#0x1_multisig_account_create_multisig_account)
-  [Function `create_multisig_account_seed`](#0x1_multisig_account_create_multisig_account_seed)
-  [Function `validate_owners`](#0x1_multisig_account_validate_owners)
-  [Function `assert_is_owner`](#0x1_multisig_account_assert_is_owner)
-  [Function `assert_multisig_account_exists`](#0x1_multisig_account_assert_multisig_account_exists)


<pre><code><b>use</b> <a href="account.md#0x1_account">0x1::account</a>;
<b>use</b> <a href="aptos_coin.md#0x1_aptos_coin">0x1::aptos_coin</a>;
<b>use</b> <a href="../../aptos-stdlib/../move-stdlib/doc/bcs.md#0x1_bcs">0x1::bcs</a>;
<b>use</b> <a href="chain_id.md#0x1_chain_id">0x1::chain_id</a>;
<b>use</b> <a href="coin.md#0x1_coin">0x1::coin</a>;
<b>use</b> <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error">0x1::error</a>;
<b>use</b> <a href="event.md#0x1_event">0x1::event</a>;
<b>use</b> <a href="../../aptos-stdlib/doc/hash.md#0x1_hash">0x1::hash</a>;
<b>use</b> <a href="../../aptos-stdlib/../move-stdlib/doc/option.md#0x1_option">0x1::option</a>;
<b>use</b> <a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">0x1::signer</a>;
<b>use</b> <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map">0x1::simple_map</a>;
<b>use</b> <a href="../../aptos-stdlib/../move-stdlib/doc/string.md#0x1_string">0x1::string</a>;
<b>use</b> <a href="../../aptos-stdlib/doc/table.md#0x1_table">0x1::table</a>;
<b>use</b> <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">0x1::vector</a>;
</code></pre>



<a name="0x1_multisig_account_MultisigAccount"></a>

## Resource `MultisigAccount`

Represents a multisig account's configurations and transactions.
This will be stored in the multisig account (created as a resource account separate from any owner accounts).


<pre><code><b>struct</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> <b>has</b> key
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>owners: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>signatures_required: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>transactions: <a href="../../aptos-stdlib/doc/table.md#0x1_table_Table">table::Table</a>&lt;u64, <a href="multisig_account.md#0x1_multisig_account_MultisigTransaction">multisig_account::MultisigTransaction</a>&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>last_transaction_id: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>next_transaction_id: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>signer_cap: <a href="../../aptos-stdlib/../move-stdlib/doc/option.md#0x1_option_Option">option::Option</a>&lt;<a href="account.md#0x1_account_SignerCapability">account::SignerCapability</a>&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>add_owners_events: <a href="event.md#0x1_event_EventHandle">event::EventHandle</a>&lt;<a href="multisig_account.md#0x1_multisig_account_AddOwnersEvent">multisig_account::AddOwnersEvent</a>&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>remove_owners_events: <a href="event.md#0x1_event_EventHandle">event::EventHandle</a>&lt;<a href="multisig_account.md#0x1_multisig_account_RemoveOwnersEvent">multisig_account::RemoveOwnersEvent</a>&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>update_signature_required_events: <a href="event.md#0x1_event_EventHandle">event::EventHandle</a>&lt;<a href="multisig_account.md#0x1_multisig_account_UpdateSignaturesRequiredEvent">multisig_account::UpdateSignaturesRequiredEvent</a>&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>create_transaction_events: <a href="event.md#0x1_event_EventHandle">event::EventHandle</a>&lt;<a href="multisig_account.md#0x1_multisig_account_CreateTransactionEvent">multisig_account::CreateTransactionEvent</a>&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>approve_transaction_events: <a href="event.md#0x1_event_EventHandle">event::EventHandle</a>&lt;<a href="multisig_account.md#0x1_multisig_account_ApproveTransactionEvent">multisig_account::ApproveTransactionEvent</a>&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>reject_transaction_events: <a href="event.md#0x1_event_EventHandle">event::EventHandle</a>&lt;<a href="multisig_account.md#0x1_multisig_account_RejectTransactionEvent">multisig_account::RejectTransactionEvent</a>&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>execute_transaction_events: <a href="event.md#0x1_event_EventHandle">event::EventHandle</a>&lt;<a href="multisig_account.md#0x1_multisig_account_ExecuteTransactionEvent">multisig_account::ExecuteTransactionEvent</a>&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>remove_transaction_events: <a href="event.md#0x1_event_EventHandle">event::EventHandle</a>&lt;<a href="multisig_account.md#0x1_multisig_account_RemoveTransactionEvent">multisig_account::RemoveTransactionEvent</a>&gt;</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_multisig_account_MultisigTransaction"></a>

## Struct `MultisigTransaction`

A transaction to be executed in a multisig account.
This must contain either the full transaction payload or its hash (stored as bytes).


<pre><code><b>struct</b> <a href="multisig_account.md#0x1_multisig_account_MultisigTransaction">MultisigTransaction</a> <b>has</b> <b>copy</b>, drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>payload: <a href="../../aptos-stdlib/../move-stdlib/doc/option.md#0x1_option_Option">option::Option</a>&lt;<a href="multisig_account.md#0x1_multisig_account_TransactionPayload">multisig_account::TransactionPayload</a>&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>payload_hash: <a href="../../aptos-stdlib/../move-stdlib/doc/option.md#0x1_option_Option">option::Option</a>&lt;<a href="multisig_account.md#0x1_multisig_account_PayloadHash">multisig_account::PayloadHash</a>&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>approvals: <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_SimpleMap">simple_map::SimpleMap</a>&lt;<b>address</b>, bool&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>rejections: <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_SimpleMap">simple_map::SimpleMap</a>&lt;<b>address</b>, bool&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>creator: <b>address</b></code>
</dt>
<dd>

</dd>
<dt>
<code>metadata: <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_SimpleMap">simple_map::SimpleMap</a>&lt;<a href="../../aptos-stdlib/../move-stdlib/doc/string.md#0x1_string_String">string::String</a>, <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;&gt;</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_multisig_account_TransactionPayload"></a>

## Struct `TransactionPayload`

The payload of the transaction to store on chain.


<pre><code><b>struct</b> <a href="multisig_account.md#0x1_multisig_account_TransactionPayload">TransactionPayload</a> <b>has</b> <b>copy</b>, drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>target_function: <a href="../../aptos-stdlib/../move-stdlib/doc/string.md#0x1_string_String">string::String</a></code>
</dt>
<dd>

</dd>
<dt>
<code>args: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_multisig_account_PayloadHash"></a>

## Struct `PayloadHash`

The hash of the multisig transaction payload.


<pre><code><b>struct</b> <a href="multisig_account.md#0x1_multisig_account_PayloadHash">PayloadHash</a> <b>has</b> <b>copy</b>, drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>function_hash: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>args_hash: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_multisig_account_MultisigAccountCreationMessage"></a>

## Struct `MultisigAccountCreationMessage`

Used only for vierfying multisig account creation on top of existing accounts.


<pre><code><b>struct</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccountCreationMessage">MultisigAccountCreationMessage</a> <b>has</b> <b>copy</b>, drop
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code><a href="chain_id.md#0x1_chain_id">chain_id</a>: u8</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_multisig_account_AddOwnersEvent"></a>

## Struct `AddOwnersEvent`

Event emitted when new owners are added to the multisig account.


<pre><code><b>struct</b> <a href="multisig_account.md#0x1_multisig_account_AddOwnersEvent">AddOwnersEvent</a> <b>has</b> drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>owners_added: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_multisig_account_RemoveOwnersEvent"></a>

## Struct `RemoveOwnersEvent`

Event emitted when new owners are removed from the multisig account.


<pre><code><b>struct</b> <a href="multisig_account.md#0x1_multisig_account_RemoveOwnersEvent">RemoveOwnersEvent</a> <b>has</b> drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>owners_removed: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_multisig_account_UpdateSignaturesRequiredEvent"></a>

## Struct `UpdateSignaturesRequiredEvent`

Event emitted when the number of signatures required is updated.


<pre><code><b>struct</b> <a href="multisig_account.md#0x1_multisig_account_UpdateSignaturesRequiredEvent">UpdateSignaturesRequiredEvent</a> <b>has</b> drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>old_signatures_required: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>new_signatures_required: u64</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_multisig_account_CreateTransactionEvent"></a>

## Struct `CreateTransactionEvent`

Event emitted when a transaction is created.


<pre><code><b>struct</b> <a href="multisig_account.md#0x1_multisig_account_CreateTransactionEvent">CreateTransactionEvent</a> <b>has</b> drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>transaction_id: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>transaction: <a href="multisig_account.md#0x1_multisig_account_MultisigTransaction">multisig_account::MultisigTransaction</a></code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_multisig_account_ApproveTransactionEvent"></a>

## Struct `ApproveTransactionEvent`

Event emitted when an owner approves a transaction.


<pre><code><b>struct</b> <a href="multisig_account.md#0x1_multisig_account_ApproveTransactionEvent">ApproveTransactionEvent</a> <b>has</b> drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>transaction_id: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>owner: <b>address</b></code>
</dt>
<dd>

</dd>
<dt>
<code>num_approvals: u64</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_multisig_account_RejectTransactionEvent"></a>

## Struct `RejectTransactionEvent`

Event emitted when an owner rejects a transaction.


<pre><code><b>struct</b> <a href="multisig_account.md#0x1_multisig_account_RejectTransactionEvent">RejectTransactionEvent</a> <b>has</b> drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>transaction_id: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>owner: <b>address</b></code>
</dt>
<dd>

</dd>
<dt>
<code>num_rejections: u64</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_multisig_account_RemoveTransactionEvent"></a>

## Struct `RemoveTransactionEvent`

Event emitted when a transaction is officially removed because the number of rejections has reached the
number of signatures required.


<pre><code><b>struct</b> <a href="multisig_account.md#0x1_multisig_account_RemoveTransactionEvent">RemoveTransactionEvent</a> <b>has</b> drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>transaction_id: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>num_rejections: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>executor: <b>address</b></code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x1_multisig_account_ExecuteTransactionEvent"></a>

## Struct `ExecuteTransactionEvent`

Event emitted when a transaction is executed.


<pre><code><b>struct</b> <a href="multisig_account.md#0x1_multisig_account_ExecuteTransactionEvent">ExecuteTransactionEvent</a> <b>has</b> drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>transaction_id: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>transaction_payload: <a href="multisig_account.md#0x1_multisig_account_TransactionPayload">multisig_account::TransactionPayload</a></code>
</dt>
<dd>

</dd>
<dt>
<code>num_approvals: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>executor: <b>address</b></code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="@Constants_0"></a>

## Constants


<a name="0x1_multisig_account_DOMAIN_SEPARATOR"></a>

The salt used to create a resource account during multisig account creation.
This is used to avoid conflicts with other modules that also create resource accounts with the same owner
account.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_DOMAIN_SEPARATOR">DOMAIN_SEPARATOR</a>: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt; = [97, 112, 116, 111, 115, 95, 102, 114, 97, 109, 101, 119, 111, 114, 107, 58, 58, 109, 117, 108, 116, 105, 115, 105, 103, 95, 97, 99, 99, 111, 117, 110, 116];
</code></pre>



<a name="0x1_multisig_account_EACCOUNT_NOT_MULTISIG"></a>

Specified account is not a multisig account.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_EACCOUNT_NOT_MULTISIG">EACCOUNT_NOT_MULTISIG</a>: u64 = 2;
</code></pre>



<a name="0x1_multisig_account_EARGUMENTS_DOES_NOT_MATCH_HASH"></a>

Provided arguments do not match the hash stored in the on-chain transaction.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_EARGUMENTS_DOES_NOT_MATCH_HASH">EARGUMENTS_DOES_NOT_MATCH_HASH</a>: u64 = 10;
</code></pre>



<a name="0x1_multisig_account_EDUPLICATE_OWNER"></a>

Owner list cannot contain the same address more than once.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_EDUPLICATE_OWNER">EDUPLICATE_OWNER</a>: u64 = 1;
</code></pre>



<a name="0x1_multisig_account_EINVALID_FUNCTION_ARGS_HASH"></a>

Function args hash must be exactly 32 bytes (sha3-256).


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_EINVALID_FUNCTION_ARGS_HASH">EINVALID_FUNCTION_ARGS_HASH</a>: u64 = 14;
</code></pre>



<a name="0x1_multisig_account_EINVALID_FUNCTION_HASH"></a>

Function hash must be exactly 32 bytes (sha3-256).


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_EINVALID_FUNCTION_HASH">EINVALID_FUNCTION_HASH</a>: u64 = 6;
</code></pre>



<a name="0x1_multisig_account_EINVALID_SIGNATURES_REQUIRED"></a>

Number of signatures required must be more than zero and at most the total number of owners.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_EINVALID_SIGNATURES_REQUIRED">EINVALID_SIGNATURES_REQUIRED</a>: u64 = 13;
</code></pre>



<a name="0x1_multisig_account_ENOT_ENOUGH_APPROVALS"></a>

Transaction has not received enough approvals to be executed.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_ENOT_ENOUGH_APPROVALS">ENOT_ENOUGH_APPROVALS</a>: u64 = 11;
</code></pre>



<a name="0x1_multisig_account_ENOT_ENOUGH_OWNERS"></a>

Multisig account must have at least one owner.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_ENOT_ENOUGH_OWNERS">ENOT_ENOUGH_OWNERS</a>: u64 = 5;
</code></pre>



<a name="0x1_multisig_account_ENOT_ENOUGH_REJECTIONS"></a>

Transaction has not received enough rejections to be removed.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_ENOT_ENOUGH_REJECTIONS">ENOT_ENOUGH_REJECTIONS</a>: u64 = 12;
</code></pre>



<a name="0x1_multisig_account_ENOT_OWNER"></a>

Account executing this operation is not an owner of the multisig account.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_ENOT_OWNER">ENOT_OWNER</a>: u64 = 3;
</code></pre>



<a name="0x1_multisig_account_EOWNER_CANNOT_BE_MULTISIG_ACCOUNT_ITSELF"></a>

The multisig account itself cannot be an owner.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_EOWNER_CANNOT_BE_MULTISIG_ACCOUNT_ITSELF">EOWNER_CANNOT_BE_MULTISIG_ACCOUNT_ITSELF</a>: u64 = 15;
</code></pre>



<a name="0x1_multisig_account_EPAYLOAD_NOT_STORED"></a>

Cannot execute the specified transaction simply via transaction_id as the full payload is not stored on chain.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_EPAYLOAD_NOT_STORED">EPAYLOAD_NOT_STORED</a>: u64 = 8;
</code></pre>



<a name="0x1_multisig_account_ETARGET_FUNCTION_CANNOT_BE_EMPTY"></a>

Target function cannot be empty.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_ETARGET_FUNCTION_CANNOT_BE_EMPTY">ETARGET_FUNCTION_CANNOT_BE_EMPTY</a>: u64 = 4;
</code></pre>



<a name="0x1_multisig_account_ETARGET_FUNCTION_DOES_NOT_MATCH_HASH"></a>

Provided target function does not match the hash stored in the on-chain transaction.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_ETARGET_FUNCTION_DOES_NOT_MATCH_HASH">ETARGET_FUNCTION_DOES_NOT_MATCH_HASH</a>: u64 = 9;
</code></pre>



<a name="0x1_multisig_account_ETRANSACTION_NOT_FOUND"></a>

Transaction with specified id cannot be found. It either has not been created or has already been executed.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_ETRANSACTION_NOT_FOUND">ETRANSACTION_NOT_FOUND</a>: u64 = 7;
</code></pre>



<a name="0x1_multisig_account_TRANSACTION_HAS_ALREADY_BEEN_APPROVED"></a>

Owner has already approved this transaction before.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_TRANSACTION_HAS_ALREADY_BEEN_APPROVED">TRANSACTION_HAS_ALREADY_BEEN_APPROVED</a>: u64 = 16;
</code></pre>



<a name="0x1_multisig_account_TRANSACTION_HAS_ALREADY_BEEN_REJECTED"></a>

Owner has already rejected this transaction before.


<pre><code><b>const</b> <a href="multisig_account.md#0x1_multisig_account_TRANSACTION_HAS_ALREADY_BEEN_REJECTED">TRANSACTION_HAS_ALREADY_BEEN_REJECTED</a>: u64 = 17;
</code></pre>



<a name="0x1_multisig_account_signatures_required"></a>

## Function `signatures_required`



<pre><code><b>public</b> <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_signatures_required">signatures_required</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_signatures_required">signatures_required</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>): u64 <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    <b>borrow_global</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>).signatures_required
}
</code></pre>



</details>

<a name="0x1_multisig_account_owners"></a>

## Function `owners`



<pre><code><b>public</b> <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_owners">owners</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>): <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_owners">owners</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>): <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt; <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    <b>borrow_global</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>).owners
}
</code></pre>



</details>

<a name="0x1_multisig_account_get_transaction"></a>

## Function `get_transaction`



<pre><code><b>public</b> <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_get_transaction">get_transaction</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>, transaction_id: u64): <a href="multisig_account.md#0x1_multisig_account_MultisigTransaction">multisig_account::MultisigTransaction</a>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_get_transaction">get_transaction</a>(
    <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>,
    transaction_id: u64,
): <a href="multisig_account.md#0x1_multisig_account_MultisigTransaction">MultisigTransaction</a> <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    *<a href="../../aptos-stdlib/doc/table.md#0x1_table_borrow">table::borrow</a>(&<b>borrow_global</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>).transactions, transaction_id)
}
</code></pre>



</details>

<a name="0x1_multisig_account_can_be_executed"></a>

## Function `can_be_executed`



<pre><code><b>public</b> <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_can_be_executed">can_be_executed</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>, transaction_id: u64): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_can_be_executed">can_be_executed</a>(
    <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>, transaction_id: u64): bool <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    <b>let</b> multisig_account_resource = <b>borrow_global_mut</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <b>let</b> transaction = <a href="../../aptos-stdlib/doc/table.md#0x1_table_borrow">table::borrow</a>(&<b>mut</b> multisig_account_resource.transactions, transaction_id);
    transaction_id == multisig_account_resource.last_transaction_id + 1 &&
        <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_length">simple_map::length</a>(&transaction.approvals) &gt;= multisig_account_resource.signatures_required
}
</code></pre>



</details>

<a name="0x1_multisig_account_can_be_removed"></a>

## Function `can_be_removed`



<pre><code><b>public</b> <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_can_be_removed">can_be_removed</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>, transaction_id: u64): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_can_be_removed">can_be_removed</a>(
    <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>, transaction_id: u64): bool <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    <b>let</b> multisig_account_resource = <b>borrow_global_mut</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <b>let</b> transaction = <a href="../../aptos-stdlib/doc/table.md#0x1_table_borrow">table::borrow</a>(&<b>mut</b> multisig_account_resource.transactions, transaction_id);
    transaction_id == multisig_account_resource.last_transaction_id + 1 &&
        <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_length">simple_map::length</a>(&transaction.rejections) &gt;= multisig_account_resource.signatures_required
}
</code></pre>



</details>

<a name="0x1_multisig_account_get_next_multisig_account_address"></a>

## Function `get_next_multisig_account_address`



<pre><code><b>public</b> <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_get_next_multisig_account_address">get_next_multisig_account_address</a>(creator: <b>address</b>): <b>address</b>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_get_next_multisig_account_address">get_next_multisig_account_address</a>(creator: <b>address</b>): <b>address</b> {
    <b>let</b> owner_nonce = <a href="account.md#0x1_account_get_sequence_number">account::get_sequence_number</a>(creator);
    create_resource_address(&creator, <a href="multisig_account.md#0x1_multisig_account_create_multisig_account_seed">create_multisig_account_seed</a>(to_bytes(&owner_nonce)))
}
</code></pre>



</details>

<a name="0x1_multisig_account_last_resolved_transaction_id"></a>

## Function `last_resolved_transaction_id`

Return the id of the last transaction that was executed or removed.


<pre><code><b>public</b> <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_last_resolved_transaction_id">last_resolved_transaction_id</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_last_resolved_transaction_id">last_resolved_transaction_id</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>): u64 <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    <b>let</b> multisig_account_resource = <b>borrow_global_mut</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    multisig_account_resource.last_transaction_id
}
</code></pre>



</details>

<a name="0x1_multisig_account_create_with_existing_account"></a>

## Function `create_with_existing_account`

Creates a new multisig account on top of an existing account.

This offers a migration path for an existing account with a multi-ed25519 auth key (native multisig account).
In order to ensure a malicious module cannot obtain backdoor control over an existing account, a signed message
with a valid signature from the account's auth key is required.


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create_with_existing_account">create_with_existing_account</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, owners: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;, signatures_required: u64, account_scheme: u8, account_public_key: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;, create_multisig_account_signed_message: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create_with_existing_account">create_with_existing_account</a>(
    <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>,
    owners: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;,
    signatures_required: u64,
    account_scheme: u8,
    account_public_key: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    create_multisig_account_signed_message: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
) {
    // Verify that the `<a href="multisig_account.md#0x1_multisig_account_MultisigAccountCreationMessage">MultisigAccountCreationMessage</a>` <b>has</b> the right information and is signed by the <a href="account.md#0x1_account">account</a>
    // owner's key.
    <b>let</b> proof_challenge = <a href="multisig_account.md#0x1_multisig_account_MultisigAccountCreationMessage">MultisigAccountCreationMessage</a> {
        <a href="chain_id.md#0x1_chain_id">chain_id</a>: <a href="chain_id.md#0x1_chain_id_get">chain_id::get</a>(),
    };
    <a href="account.md#0x1_account_verify_signed_message">account::verify_signed_message</a>(
        address_of(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>),
        account_scheme,
        account_public_key,
        create_multisig_account_signed_message,
        proof_challenge,
    );

    <a href="multisig_account.md#0x1_multisig_account_create_with_owners_internal">create_with_owners_internal</a>(
        <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>,
        owners,
        signatures_required,
        <a href="../../aptos-stdlib/../move-stdlib/doc/option.md#0x1_option_none">option::none</a>&lt;SignerCapability&gt;(),
    );
}
</code></pre>



</details>

<a name="0x1_multisig_account_create"></a>

## Function `create`

Creates a new multisig account and add the signer as a single owner.


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create">create</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, signatures_required: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create">create</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, signatures_required: u64) {
    <a href="multisig_account.md#0x1_multisig_account_create_with_owners">create_with_owners</a>(owner, <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>[], signatures_required);
}
</code></pre>



</details>

<a name="0x1_multisig_account_create_with_owners"></a>

## Function `create_with_owners`

Creates a new multisig account with the specified additional owner list and signatures required.

@param additional_owners The owner account who calls this function cannot be in the additional_owners and there
cannot be any duplicate owners in the list.
@param signatures_require The number of signatures required to execute a transaction. Must be at least 1 and
at most the total number of owners.


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create_with_owners">create_with_owners</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, additional_owners: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;, signatures_required: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create_with_owners">create_with_owners</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, additional_owners: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;, signatures_required: u64) {
    <b>let</b> (<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>, multisig_signer_cap) = <a href="multisig_account.md#0x1_multisig_account_create_multisig_account">create_multisig_account</a>(owner);
    <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_push_back">vector::push_back</a>(&<b>mut</b> additional_owners, address_of(owner));
    <a href="multisig_account.md#0x1_multisig_account_create_with_owners_internal">create_with_owners_internal</a>(
        &<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>,
        additional_owners,
        signatures_required,
        <a href="../../aptos-stdlib/../move-stdlib/doc/option.md#0x1_option_some">option::some</a>(multisig_signer_cap),
    );
}
</code></pre>



</details>

<a name="0x1_multisig_account_create_with_owners_internal"></a>

## Function `create_with_owners_internal`



<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create_with_owners_internal">create_with_owners_internal</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, owners: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;, signatures_required: u64, multisig_account_signer_cap: <a href="../../aptos-stdlib/../move-stdlib/doc/option.md#0x1_option_Option">option::Option</a>&lt;<a href="account.md#0x1_account_SignerCapability">account::SignerCapability</a>&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create_with_owners_internal">create_with_owners_internal</a>(
    <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>,
    owners: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;,
    signatures_required: u64,
    multisig_account_signer_cap: Option&lt;SignerCapability&gt;,
) {
    <b>assert</b>!(
        signatures_required &gt; 0 && <a href="multisig_account.md#0x1_multisig_account_signatures_required">signatures_required</a> &lt;= <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_length">vector::length</a>(&owners),
        <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_invalid_argument">error::invalid_argument</a>(<a href="multisig_account.md#0x1_multisig_account_EINVALID_SIGNATURES_REQUIRED">EINVALID_SIGNATURES_REQUIRED</a>),
    );

    <a href="multisig_account.md#0x1_multisig_account_validate_owners">validate_owners</a>(&owners, address_of(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>));
    <b>move_to</b>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>, <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
        owners,
        signatures_required,
        transactions: <a href="../../aptos-stdlib/doc/table.md#0x1_table_new">table::new</a>&lt;u64, <a href="multisig_account.md#0x1_multisig_account_MultisigTransaction">MultisigTransaction</a>&gt;(),
        // First transaction will start at id 1 instead of 0.
        last_transaction_id: 0,
        next_transaction_id: 1,
        signer_cap: multisig_account_signer_cap,
        add_owners_events: new_event_handle&lt;<a href="multisig_account.md#0x1_multisig_account_AddOwnersEvent">AddOwnersEvent</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>),
        remove_owners_events: new_event_handle&lt;<a href="multisig_account.md#0x1_multisig_account_RemoveOwnersEvent">RemoveOwnersEvent</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>),
        update_signature_required_events: new_event_handle&lt;<a href="multisig_account.md#0x1_multisig_account_UpdateSignaturesRequiredEvent">UpdateSignaturesRequiredEvent</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>),
        create_transaction_events: new_event_handle&lt;<a href="multisig_account.md#0x1_multisig_account_CreateTransactionEvent">CreateTransactionEvent</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>),
        approve_transaction_events: new_event_handle&lt;<a href="multisig_account.md#0x1_multisig_account_ApproveTransactionEvent">ApproveTransactionEvent</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>),
        reject_transaction_events: new_event_handle&lt;<a href="multisig_account.md#0x1_multisig_account_RejectTransactionEvent">RejectTransactionEvent</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>),
        execute_transaction_events: new_event_handle&lt;<a href="multisig_account.md#0x1_multisig_account_ExecuteTransactionEvent">ExecuteTransactionEvent</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>),
        remove_transaction_events: new_event_handle&lt;<a href="multisig_account.md#0x1_multisig_account_RemoveTransactionEvent">RemoveTransactionEvent</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>),
    });
}
</code></pre>



</details>

<a name="0x1_multisig_account_add_owners"></a>

## Function `add_owners`

Add new owners to the multisig account. This can only be invoked by the multisig account itself, through the
proposal flow.

Note that this function is not public so it can only be invoked directly instead of via a module or script. This
ensures that a multisig transaction cannot lead to another module obtaining the multisig signer and using it to
maliciously alter the owners list.


<pre><code>entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_add_owners">add_owners</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, new_owners: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code>entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_add_owners">add_owners</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, new_owners: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;) <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    // Short circuit <b>if</b> new owners list is empty.
    // This avoids emitting an <a href="event.md#0x1_event">event</a> <b>if</b> no changes happen, which is confusing <b>to</b> off-chain components.
    <b>if</b> (<a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_length">vector::length</a>(&new_owners) == 0) {
        <b>return</b>
    };

    <b>let</b> multisig_address = address_of(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <a href="multisig_account.md#0x1_multisig_account_assert_multisig_account_exists">assert_multisig_account_exists</a>(multisig_address);
    <b>let</b> multisig_account_resource = <b>borrow_global_mut</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(multisig_address);

    <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_append">vector::append</a>(&<b>mut</b> multisig_account_resource.owners, new_owners);
    <a href="multisig_account.md#0x1_multisig_account_validate_owners">validate_owners</a>(&multisig_account_resource.owners, multisig_address);
    emit_event(&<b>mut</b> multisig_account_resource.add_owners_events, <a href="multisig_account.md#0x1_multisig_account_AddOwnersEvent">AddOwnersEvent</a> {
        owners_added: new_owners,
    });
}
</code></pre>



</details>

<a name="0x1_multisig_account_remove_owners"></a>

## Function `remove_owners`

Remove owners from the multisig account. This can only be invoked by the multisig account itself, through the
proposal flow.

This function skips any owners who are not in the multisig account's list of owners.
Note that this function is not public so it can only be invoked directly instead of via a module or script. This
ensures that a multisig transaction cannot lead to another module obtaining the multisig signer and using it to
maliciously alter the owners list.


<pre><code>entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_remove_owners">remove_owners</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, owners_to_remove: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code>entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_remove_owners">remove_owners</a>(
    <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, owners_to_remove: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;) <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    // Short circuit <b>if</b> the list of owners <b>to</b> remove is empty.
    // This avoids emitting an <a href="event.md#0x1_event">event</a> <b>if</b> no changes happen, which is confusing <b>to</b> off-chain components.
    <b>if</b> (<a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_length">vector::length</a>(&owners_to_remove) == 0) {
        <b>return</b>
    };

    <b>let</b> multisig_address = address_of(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <a href="multisig_account.md#0x1_multisig_account_assert_multisig_account_exists">assert_multisig_account_exists</a>(multisig_address);
    <b>let</b> multisig_account_resource = <b>borrow_global_mut</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(multisig_address);

    <b>let</b> i = 0;
    <b>let</b> len = <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_length">vector::length</a>(&owners_to_remove);
    <b>let</b> owners = &<b>mut</b> multisig_account_resource.owners;
    <b>let</b> owners_removed = <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_empty">vector::empty</a>&lt;<b>address</b>&gt;();
    <b>while</b> (i &lt; len) {
        <b>let</b> owner_to_remove = *<a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_borrow">vector::borrow</a>(&owners_to_remove, i);
        <b>let</b> (found, index) = <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_index_of">vector::index_of</a>(owners, &owner_to_remove);
        // Only remove an owner <b>if</b> they're present in the owners list.
        <b>if</b> (found) {
            <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_push_back">vector::push_back</a>(&<b>mut</b> owners_removed, owner_to_remove);
            <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_swap_remove">vector::swap_remove</a>(owners, index);
        };
        i = i + 1;
    };

    // Make sure there's still at least <b>as</b> many owners <b>as</b> the number of signatures required.
    // This also <b>ensures</b> that there's at least one owner left <b>as</b> signature threshold must be &gt; 0.
    <b>assert</b>!(
        <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_length">vector::length</a>(owners) &gt;= multisig_account_resource.signatures_required,
        <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_invalid_state">error::invalid_state</a>(<a href="multisig_account.md#0x1_multisig_account_ENOT_ENOUGH_OWNERS">ENOT_ENOUGH_OWNERS</a>),
    );

    emit_event(&<b>mut</b> multisig_account_resource.remove_owners_events, <a href="multisig_account.md#0x1_multisig_account_RemoveOwnersEvent">RemoveOwnersEvent</a> { owners_removed });
}
</code></pre>



</details>

<a name="0x1_multisig_account_update_signatures_required"></a>

## Function `update_signatures_required`

Update the number of signatures required to execute transaction in the specified multisig account.

This can only be invoked by the multisig account itself, through the proposal flow.
Note that this function is not public so it can only be invoked directly instead of via a module or script. This
ensures that a multisig transaction cannot lead to another module obtaining the multisig signer and using it to
maliciously alter the number of signatures required.


<pre><code>entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_update_signatures_required">update_signatures_required</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, new_signatures_required: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code>entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_update_signatures_required">update_signatures_required</a>(
    <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, new_signatures_required: u64) <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    <b>let</b> multisig_address = address_of(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <a href="multisig_account.md#0x1_multisig_account_assert_multisig_account_exists">assert_multisig_account_exists</a>(multisig_address);
    <b>let</b> multisig_account_resource = <b>borrow_global_mut</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(multisig_address);
    // Short-circuit <b>if</b> the new number of signatures required is the same <b>as</b> before.
    // This avoids emitting an <a href="event.md#0x1_event">event</a>.
    <b>if</b> (multisig_account_resource.signatures_required == new_signatures_required) {
        <b>return</b>
    };
    <b>let</b> num_owners = <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_length">vector::length</a>(&multisig_account_resource.owners);
    <b>assert</b>!(
        new_signatures_required &gt; 0 && new_signatures_required &lt;= num_owners,
        <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_invalid_argument">error::invalid_argument</a>(<a href="multisig_account.md#0x1_multisig_account_EINVALID_SIGNATURES_REQUIRED">EINVALID_SIGNATURES_REQUIRED</a>),
    );

    <b>let</b> old_signatures_required = multisig_account_resource.signatures_required;
    multisig_account_resource.signatures_required = new_signatures_required;
    emit_event(
        &<b>mut</b> multisig_account_resource.update_signature_required_events,
        <a href="multisig_account.md#0x1_multisig_account_UpdateSignaturesRequiredEvent">UpdateSignaturesRequiredEvent</a> {
            old_signatures_required,
            new_signatures_required,
        }
    );
}
</code></pre>



</details>

<a name="0x1_multisig_account_create_transaction"></a>

## Function `create_transaction`

Create a multisig transaction, which will have one approval initially (from the creator).

@param target_function The target function to call such as 0x123::module_to_call::function_to_call.
@param args Vector of BCS-encoded argument values to invoke the target function with.


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create_transaction">create_transaction</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>, target_function: <a href="../../aptos-stdlib/../move-stdlib/doc/string.md#0x1_string_String">string::String</a>, args: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create_transaction">create_transaction</a>(
    owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>,
    <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>,
    target_function: String,
    args: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
) <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    <b>assert</b>!(<a href="../../aptos-stdlib/../move-stdlib/doc/string.md#0x1_string_length">string::length</a>(&target_function) &gt; 0, <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_invalid_argument">error::invalid_argument</a>(<a href="multisig_account.md#0x1_multisig_account_ETARGET_FUNCTION_CANNOT_BE_EMPTY">ETARGET_FUNCTION_CANNOT_BE_EMPTY</a>));

    <a href="multisig_account.md#0x1_multisig_account_assert_multisig_account_exists">assert_multisig_account_exists</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <b>let</b> multisig_account_resource = <b>borrow_global_mut</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <a href="multisig_account.md#0x1_multisig_account_assert_is_owner">assert_is_owner</a>(owner, multisig_account_resource);

    <b>let</b> creator = address_of(owner);
    <b>let</b> transaction = <a href="multisig_account.md#0x1_multisig_account_MultisigTransaction">MultisigTransaction</a> {
        payload: <a href="../../aptos-stdlib/../move-stdlib/doc/option.md#0x1_option_some">option::some</a>(<a href="multisig_account.md#0x1_multisig_account_TransactionPayload">TransactionPayload</a> { target_function, args }),
        payload_hash: <a href="../../aptos-stdlib/../move-stdlib/doc/option.md#0x1_option_none">option::none</a>&lt;<a href="multisig_account.md#0x1_multisig_account_PayloadHash">PayloadHash</a>&gt;(),
        approvals: <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_create">simple_map::create</a>&lt;<b>address</b>, bool&gt;(),
        rejections: <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_create">simple_map::create</a>&lt;<b>address</b>, bool&gt;(),
        creator,
        metadata: <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_create">simple_map::create</a>&lt;String, <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;&gt;(),
    };
    <a href="multisig_account.md#0x1_multisig_account_add_transaction">add_transaction</a>(creator, multisig_account_resource, transaction);
}
</code></pre>



</details>

<a name="0x1_multisig_account_create_transaction_with_hash"></a>

## Function `create_transaction_with_hash`

Create a multisig transaction with a transaction hash instead of the full payload.
This means the payload will be stored off chain for gas saving. Later, during execution, the executor will need
to provide the full payload, which will be validated against the hash stored on-chain.

@param function_hash The sha-256 hash of the function to invoke, e.g. 0x123::module_to_call::function_to_call.
@param args_hash The sha-256 hash of the function arguments - a concatenated vector of the bcs-encoded
function arguments.


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create_transaction_with_hash">create_transaction_with_hash</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>, function_hash: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;, args_hash: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create_transaction_with_hash">create_transaction_with_hash</a>(
    owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>,
    <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>,
    function_hash: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    args_hash: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
) <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    // These are sha3-256 hashes so they must be exactly 32 bytes.
    <b>assert</b>!(<a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_length">vector::length</a>(&function_hash) == 32, <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_invalid_argument">error::invalid_argument</a>(<a href="multisig_account.md#0x1_multisig_account_EINVALID_FUNCTION_HASH">EINVALID_FUNCTION_HASH</a>));
    <b>assert</b>!(<a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_length">vector::length</a>(&args_hash) == 32, <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_invalid_argument">error::invalid_argument</a>(<a href="multisig_account.md#0x1_multisig_account_EINVALID_FUNCTION_ARGS_HASH">EINVALID_FUNCTION_ARGS_HASH</a>));

    <a href="multisig_account.md#0x1_multisig_account_assert_multisig_account_exists">assert_multisig_account_exists</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <b>let</b> multisig_account_resource = <b>borrow_global_mut</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <a href="multisig_account.md#0x1_multisig_account_assert_is_owner">assert_is_owner</a>(owner, multisig_account_resource);

    <b>let</b> creator = address_of(owner);
    <b>let</b> transaction = <a href="multisig_account.md#0x1_multisig_account_MultisigTransaction">MultisigTransaction</a> {
        payload: <a href="../../aptos-stdlib/../move-stdlib/doc/option.md#0x1_option_none">option::none</a>&lt;<a href="multisig_account.md#0x1_multisig_account_TransactionPayload">TransactionPayload</a>&gt;(),
        payload_hash: <a href="../../aptos-stdlib/../move-stdlib/doc/option.md#0x1_option_some">option::some</a>(<a href="multisig_account.md#0x1_multisig_account_PayloadHash">PayloadHash</a> { function_hash, args_hash }),
        approvals: <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_create">simple_map::create</a>&lt;<b>address</b>, bool&gt;(),
        rejections: <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_create">simple_map::create</a>&lt;<b>address</b>, bool&gt;(),
        creator,
        metadata: <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_create">simple_map::create</a>&lt;String, <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;&gt;(),
    };
    <a href="multisig_account.md#0x1_multisig_account_add_transaction">add_transaction</a>(creator, multisig_account_resource, transaction);
}
</code></pre>



</details>

<a name="0x1_multisig_account_approve_transaction"></a>

## Function `approve_transaction`

Approve a multisig transaction.


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_approve_transaction">approve_transaction</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>, transaction_id: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_approve_transaction">approve_transaction</a>(
    owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>, transaction_id: u64) <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    <a href="multisig_account.md#0x1_multisig_account_vote_transanction">vote_transanction</a>(owner, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>, transaction_id, <b>true</b>);
}
</code></pre>



</details>

<a name="0x1_multisig_account_reject_transaction"></a>

## Function `reject_transaction`

Reject a multisig transaction.


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_reject_transaction">reject_transaction</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>, transaction_id: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_reject_transaction">reject_transaction</a>(
    owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>, transaction_id: u64) <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    <a href="multisig_account.md#0x1_multisig_account_vote_transanction">vote_transanction</a>(owner, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>, transaction_id, <b>false</b>);
}
</code></pre>



</details>

<a name="0x1_multisig_account_vote_transanction"></a>

## Function `vote_transanction`

Generic function that can be used to either approve or reject a multisig transaction


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_vote_transanction">vote_transanction</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>, transaction_id: u64, approved: bool)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_vote_transanction">vote_transanction</a>(
    owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>, transaction_id: u64, approved: bool) <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    <a href="multisig_account.md#0x1_multisig_account_assert_multisig_account_exists">assert_multisig_account_exists</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <b>let</b> multisig_account_resource = <b>borrow_global_mut</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <a href="multisig_account.md#0x1_multisig_account_assert_is_owner">assert_is_owner</a>(owner, multisig_account_resource);

    <b>assert</b>!(
        <a href="../../aptos-stdlib/doc/table.md#0x1_table_contains">table::contains</a>(&multisig_account_resource.transactions, transaction_id),
        <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_not_found">error::not_found</a>(<a href="multisig_account.md#0x1_multisig_account_ETRANSACTION_NOT_FOUND">ETRANSACTION_NOT_FOUND</a>),
    );
    <b>let</b> transaction = <a href="../../aptos-stdlib/doc/table.md#0x1_table_borrow_mut">table::borrow_mut</a>(&<b>mut</b> multisig_account_resource.transactions, transaction_id);
    <b>let</b> owner_addr = address_of(owner);
    <b>if</b> (approved) {
        <b>assert</b>!(
            !<a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_contains_key">simple_map::contains_key</a>(&transaction.approvals, &owner_addr),
            <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_already_exists">error::already_exists</a>(<a href="multisig_account.md#0x1_multisig_account_TRANSACTION_HAS_ALREADY_BEEN_APPROVED">TRANSACTION_HAS_ALREADY_BEEN_APPROVED</a>)
        );
        <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_add">simple_map::add</a>(&<b>mut</b> transaction.approvals, owner_addr, <b>true</b>);
        // Revoke rejection.
        <b>if</b> (<a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_contains_key">simple_map::contains_key</a>(&<b>mut</b> transaction.rejections, &owner_addr)) {
            <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_remove">simple_map::remove</a>(&<b>mut</b> transaction.rejections, &owner_addr);
        };
        emit_event(
            &<b>mut</b> multisig_account_resource.approve_transaction_events,
            <a href="multisig_account.md#0x1_multisig_account_ApproveTransactionEvent">ApproveTransactionEvent</a> {
                owner: owner_addr,
                transaction_id,
                num_approvals: <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_length">simple_map::length</a>(&transaction.approvals),
            }
        );
    } <b>else</b> {
        <b>assert</b>!(
            !<a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_contains_key">simple_map::contains_key</a>(&transaction.rejections, &owner_addr),
            <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_already_exists">error::already_exists</a>(<a href="multisig_account.md#0x1_multisig_account_TRANSACTION_HAS_ALREADY_BEEN_REJECTED">TRANSACTION_HAS_ALREADY_BEEN_REJECTED</a>)
        );
        <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_add">simple_map::add</a>(&<b>mut</b> transaction.rejections, owner_addr, <b>true</b>);
        // Revoke approval.
        <b>if</b> (<a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_contains_key">simple_map::contains_key</a>(&<b>mut</b> transaction.approvals, &owner_addr)) {
            <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_remove">simple_map::remove</a>(&<b>mut</b> transaction.approvals, &owner_addr);
        };
        emit_event(
            &<b>mut</b> multisig_account_resource.reject_transaction_events,
            <a href="multisig_account.md#0x1_multisig_account_RejectTransactionEvent">RejectTransactionEvent</a> {
                owner: owner_addr,
                transaction_id,
                num_rejections: <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_length">simple_map::length</a>(&transaction.rejections),
            }
        );
    };
}
</code></pre>



</details>

<a name="0x1_multisig_account_remove_transaction"></a>

## Function `remove_transaction`

Remove the next transaction if it has sufficient owner rejections.


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_remove_transaction">remove_transaction</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> entry <b>fun</b> <a href="multisig_account.md#0x1_multisig_account_remove_transaction">remove_transaction</a>(
    owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>,
    <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>,
) <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    <a href="multisig_account.md#0x1_multisig_account_assert_multisig_account_exists">assert_multisig_account_exists</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <b>let</b> multisig_account_resource = <b>borrow_global_mut</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <a href="multisig_account.md#0x1_multisig_account_assert_is_owner">assert_is_owner</a>(owner, multisig_account_resource);
    <b>let</b> transaction_id = multisig_account_resource.last_transaction_id + 1;
    <b>assert</b>!(
        <a href="../../aptos-stdlib/doc/table.md#0x1_table_contains">table::contains</a>(&multisig_account_resource.transactions, transaction_id),
        <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_not_found">error::not_found</a>(<a href="multisig_account.md#0x1_multisig_account_ETRANSACTION_NOT_FOUND">ETRANSACTION_NOT_FOUND</a>),
    );
    <b>let</b> transaction = <a href="../../aptos-stdlib/doc/table.md#0x1_table_remove">table::remove</a>(&<b>mut</b> multisig_account_resource.transactions, transaction_id);
    <b>assert</b>!(
        <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_length">simple_map::length</a>(&transaction.rejections) &gt;= multisig_account_resource.signatures_required,
        <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_invalid_state">error::invalid_state</a>(<a href="multisig_account.md#0x1_multisig_account_ENOT_ENOUGH_REJECTIONS">ENOT_ENOUGH_REJECTIONS</a>),
    );

    multisig_account_resource.last_transaction_id = transaction_id;
    emit_event(
        &<b>mut</b> multisig_account_resource.remove_transaction_events,
        <a href="multisig_account.md#0x1_multisig_account_RemoveTransactionEvent">RemoveTransactionEvent</a> {
            transaction_id,
            num_rejections: <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_length">simple_map::length</a>(&transaction.rejections),
            executor: address_of(owner),
        }
    );
}
</code></pre>



</details>

<a name="0x1_multisig_account_execute_transaction"></a>

## Function `execute_transaction`

Execute the next transaction if it has enought approvals. This doesn't actually invoke the target function but
simply marks the transaction as already been executed (by removing it from the transactions table). Actual
function invocation is done as part executing the MultisigTransaction.

This function is private so no other code can call this beside the VM itself as part of MultisigTransaction.

@param target_function Optional and can be empty if the full transaction payload is stored on chain.
@param args Optional and can be empty if the full transaction payload is stored on chain.
@return The transaction payload to execute as the multisig account.


<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_execute_transaction">execute_transaction</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>, target_function: <a href="../../aptos-stdlib/../move-stdlib/doc/string.md#0x1_string_String">string::String</a>, args: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;): <a href="multisig_account.md#0x1_multisig_account_TransactionPayload">multisig_account::TransactionPayload</a>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_execute_transaction">execute_transaction</a>(
    owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>,
    <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>,
    target_function: String,
    args: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
): <a href="multisig_account.md#0x1_multisig_account_TransactionPayload">TransactionPayload</a> <b>acquires</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a> {
    <a href="multisig_account.md#0x1_multisig_account_assert_multisig_account_exists">assert_multisig_account_exists</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <b>let</b> multisig_account_resource = <b>borrow_global_mut</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>);
    <a href="multisig_account.md#0x1_multisig_account_assert_is_owner">assert_is_owner</a>(owner, multisig_account_resource);
    <b>let</b> transaction_id = multisig_account_resource.last_transaction_id + 1;
    <b>assert</b>!(
        <a href="../../aptos-stdlib/doc/table.md#0x1_table_contains">table::contains</a>(&multisig_account_resource.transactions, transaction_id),
        <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_not_found">error::not_found</a>(<a href="multisig_account.md#0x1_multisig_account_ETRANSACTION_NOT_FOUND">ETRANSACTION_NOT_FOUND</a>),
    );
    <b>let</b> transaction = <a href="../../aptos-stdlib/doc/table.md#0x1_table_remove">table::remove</a>(&<b>mut</b> multisig_account_resource.transactions, transaction_id);
    <b>assert</b>!(
        <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_length">simple_map::length</a>(&transaction.approvals) &gt;= multisig_account_resource.signatures_required,
        <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_invalid_state">error::invalid_state</a>(<a href="multisig_account.md#0x1_multisig_account_ENOT_ENOUGH_APPROVALS">ENOT_ENOUGH_APPROVALS</a>),
    );

    <b>let</b> transaction_payload =
        <b>if</b> (<a href="../../aptos-stdlib/../move-stdlib/doc/option.md#0x1_option_is_some">option::is_some</a>(&transaction.payload)) {
            <a href="../../aptos-stdlib/../move-stdlib/doc/option.md#0x1_option_extract">option::extract</a>(&<b>mut</b> transaction.payload)
        } <b>else</b> {
            <b>let</b> payload_hash = <a href="../../aptos-stdlib/../move-stdlib/doc/option.md#0x1_option_extract">option::extract</a>(&<b>mut</b> transaction.payload_hash);
            <b>assert</b>!(
                sha3_256(*<a href="../../aptos-stdlib/../move-stdlib/doc/string.md#0x1_string_bytes">string::bytes</a>(&target_function)) == payload_hash.function_hash,
                <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_invalid_argument">error::invalid_argument</a>(<a href="multisig_account.md#0x1_multisig_account_ETARGET_FUNCTION_DOES_NOT_MATCH_HASH">ETARGET_FUNCTION_DOES_NOT_MATCH_HASH</a>),
            );
            <b>assert</b>!(
                sha3_256(args) == payload_hash.args_hash,
                <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_invalid_argument">error::invalid_argument</a>(<a href="multisig_account.md#0x1_multisig_account_EARGUMENTS_DOES_NOT_MATCH_HASH">EARGUMENTS_DOES_NOT_MATCH_HASH</a>),
            );
            <a href="multisig_account.md#0x1_multisig_account_TransactionPayload">TransactionPayload</a> { target_function, args }
        };
    multisig_account_resource.last_transaction_id = transaction_id;
    emit_event(
        &<b>mut</b> multisig_account_resource.execute_transaction_events,
        <a href="multisig_account.md#0x1_multisig_account_ExecuteTransactionEvent">ExecuteTransactionEvent</a> {
            transaction_id,
            transaction_payload,
            num_approvals: <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_length">simple_map::length</a>(&transaction.approvals),
            executor: address_of(owner),
        }
    );

    transaction_payload
}
</code></pre>



</details>

<a name="0x1_multisig_account_add_transaction"></a>

## Function `add_transaction`



<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_add_transaction">add_transaction</a>(creator: <b>address</b>, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: &<b>mut</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">multisig_account::MultisigAccount</a>, transaction: <a href="multisig_account.md#0x1_multisig_account_MultisigTransaction">multisig_account::MultisigTransaction</a>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_add_transaction">add_transaction</a>(creator: <b>address</b>, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: &<b>mut</b> <a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>, transaction: <a href="multisig_account.md#0x1_multisig_account_MultisigTransaction">MultisigTransaction</a>) {
    <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_add">simple_map::add</a>(&<b>mut</b> transaction.approvals, creator, <b>true</b>);

    <b>let</b> transaction_id = <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>.next_transaction_id;
    <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>.next_transaction_id = transaction_id + 1;
    <a href="../../aptos-stdlib/doc/table.md#0x1_table_add">table::add</a>(&<b>mut</b> <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>.transactions, transaction_id, transaction);
    emit_event(
        &<b>mut</b> <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>.create_transaction_events,
        <a href="multisig_account.md#0x1_multisig_account_CreateTransactionEvent">CreateTransactionEvent</a> { transaction_id, transaction },
    );
}
</code></pre>



</details>

<a name="0x1_multisig_account_create_multisig_account"></a>

## Function `create_multisig_account`



<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create_multisig_account">create_multisig_account</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>): (<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, <a href="account.md#0x1_account_SignerCapability">account::SignerCapability</a>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create_multisig_account">create_multisig_account</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>): (<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, SignerCapability) {
    <b>let</b> owner_nonce = <a href="account.md#0x1_account_get_sequence_number">account::get_sequence_number</a>(address_of(owner));
    <b>let</b> (multisig_signer, multisig_signer_cap) =
        <a href="account.md#0x1_account_create_resource_account">account::create_resource_account</a>(owner, <a href="multisig_account.md#0x1_multisig_account_create_multisig_account_seed">create_multisig_account_seed</a>(to_bytes(&owner_nonce)));
    // Register the <a href="account.md#0x1_account">account</a> <b>to</b> receive APT <b>as</b> this is not done by default <b>as</b> part of the resource <a href="account.md#0x1_account">account</a> creation
    // flow.
    <b>if</b> (!<a href="coin.md#0x1_coin_is_account_registered">coin::is_account_registered</a>&lt;AptosCoin&gt;(address_of(&multisig_signer))) {
        <a href="coin.md#0x1_coin_register">coin::register</a>&lt;AptosCoin&gt;(&multisig_signer);
    };

    (multisig_signer, multisig_signer_cap)
}
</code></pre>



</details>

<a name="0x1_multisig_account_create_multisig_account_seed"></a>

## Function `create_multisig_account_seed`



<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create_multisig_account_seed">create_multisig_account_seed</a>(seed: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;): <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_create_multisig_account_seed">create_multisig_account_seed</a>(seed: <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt;): <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;u8&gt; {
    // Generate a seed that will be used <b>to</b> create the resource <a href="account.md#0x1_account">account</a> that hosts the staking contract.
    <b>let</b> multisig_account_seed = <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_empty">vector::empty</a>&lt;u8&gt;();
    <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_append">vector::append</a>(&<b>mut</b> multisig_account_seed, <a href="multisig_account.md#0x1_multisig_account_DOMAIN_SEPARATOR">DOMAIN_SEPARATOR</a>);
    <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_append">vector::append</a>(&<b>mut</b> multisig_account_seed, seed);

    multisig_account_seed
}
</code></pre>



</details>

<a name="0x1_multisig_account_validate_owners"></a>

## Function `validate_owners`



<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_validate_owners">validate_owners</a>(owners: &<a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_validate_owners">validate_owners</a>(owners: &<a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector">vector</a>&lt;<b>address</b>&gt;, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>) {
    <b>let</b> distinct_owners = <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_create">simple_map::create</a>&lt;<b>address</b>, bool&gt;();
    <b>let</b> i = 0;
    <b>let</b> len = <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_length">vector::length</a>(owners);
    <b>while</b> (i &lt; len) {
        <b>let</b> owner = *<a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_borrow">vector::borrow</a>(owners, i);
        <b>assert</b>!(owner != <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>, <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_invalid_argument">error::invalid_argument</a>(<a href="multisig_account.md#0x1_multisig_account_EOWNER_CANNOT_BE_MULTISIG_ACCOUNT_ITSELF">EOWNER_CANNOT_BE_MULTISIG_ACCOUNT_ITSELF</a>));
        <b>assert</b>!(
            !<a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_contains_key">simple_map::contains_key</a>(&distinct_owners, &owner),
            <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_invalid_argument">error::invalid_argument</a>(<a href="multisig_account.md#0x1_multisig_account_EDUPLICATE_OWNER">EDUPLICATE_OWNER</a>),
        );
        <a href="../../aptos-stdlib/doc/simple_map.md#0x1_simple_map_add">simple_map::add</a>(&<b>mut</b> distinct_owners, owner, <b>true</b>);
        i = i + 1;
    }
}
</code></pre>



</details>

<a name="0x1_multisig_account_assert_is_owner"></a>

## Function `assert_is_owner`



<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_assert_is_owner">assert_is_owner</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: &<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">multisig_account::MultisigAccount</a>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_assert_is_owner">assert_is_owner</a>(owner: &<a href="../../aptos-stdlib/../move-stdlib/doc/signer.md#0x1_signer">signer</a>, <a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: &<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>) {
    <b>assert</b>!(
        <a href="../../aptos-stdlib/../move-stdlib/doc/vector.md#0x1_vector_contains">vector::contains</a>(&<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>.owners, &address_of(owner)),
        <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_permission_denied">error::permission_denied</a>(<a href="multisig_account.md#0x1_multisig_account_ENOT_OWNER">ENOT_OWNER</a>),
    );
}
</code></pre>



</details>

<a name="0x1_multisig_account_assert_multisig_account_exists"></a>

## Function `assert_multisig_account_exists`



<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_assert_multisig_account_exists">assert_multisig_account_exists</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="multisig_account.md#0x1_multisig_account_assert_multisig_account_exists">assert_multisig_account_exists</a>(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>: <b>address</b>) {
    <b>assert</b>!(<b>exists</b>&lt;<a href="multisig_account.md#0x1_multisig_account_MultisigAccount">MultisigAccount</a>&gt;(<a href="multisig_account.md#0x1_multisig_account">multisig_account</a>), <a href="../../aptos-stdlib/../move-stdlib/doc/error.md#0x1_error_invalid_state">error::invalid_state</a>(<a href="multisig_account.md#0x1_multisig_account_EACCOUNT_NOT_MULTISIG">EACCOUNT_NOT_MULTISIG</a>));
}
</code></pre>



</details>


[move-book]: https://move-language.github.io/move/introduction.html
