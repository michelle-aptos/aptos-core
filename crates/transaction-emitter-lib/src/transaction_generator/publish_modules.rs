// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0
use crate::transaction_generator::{
    publishing::publish_util::PackageHandler,
    {TransactionGenerator, TransactionGeneratorCreator},
};
use aptos_infallible::RwLock;
use aptos_sdk::{
    move_types::account_address::AccountAddress,
    transaction_builder::TransactionFactory,
    types::{transaction::SignedTransaction, LocalAccount},
};
use async_trait::async_trait;
use rand::rngs::StdRng;
use std::{collections::HashMap, sync::Arc};

#[allow(dead_code)]
pub struct PublishPackageGenerator {
    rng: StdRng,
    package_handler: Arc<RwLock<PackageHandler>>,
    txn_factory: TransactionFactory,
    gas_price: u64,
}

impl PublishPackageGenerator {
    pub fn new(
        rng: StdRng,
        package_handler: Arc<RwLock<PackageHandler>>,
        txn_factory: TransactionFactory,
        gas_price: u64,
    ) -> Self {
        Self {
            rng,
            package_handler,
            txn_factory,
            gas_price,
        }
    }
}

#[async_trait]
impl TransactionGenerator for PublishPackageGenerator {
    fn generate_transactions(
        &mut self,
        accounts: Vec<&mut LocalAccount>,
        transactions_per_account: usize,
    ) -> Vec<SignedTransaction> {
        let mut requests = Vec::with_capacity(accounts.len() * transactions_per_account);
        for account in accounts {
            // First publish the module and then use it
            let package = self
                .package_handler
                .write()
                .pick_package(&mut self.rng, account);
            let txn = package.publish_transaction(account, &self.txn_factory);
            requests.push(txn);
            // use module published
            // for _ in 1..transactions_per_account - 1 {
            for _ in 1..transactions_per_account {
                let request = package.use_random_transaction(
                    &mut self.rng,
                    account,
                    &self.txn_factory,
                    self.gas_price,
                );
                requests.push(request);
            }
            // republish
            // let package = self
            //     .package_handler
            //     .write()
            //     .pick_package(&mut self.rng, account);
            // let txn = package.publish_transaction(account, &self.txn_factory);
            // requests.push(txn);
        }
        requests
    }
}

pub struct PublishPackageCreator {
    rng: StdRng,
    txn_factory: TransactionFactory,
    package_handler: Arc<RwLock<PackageHandler>>,
    gas_price: u64,
}

impl PublishPackageCreator {
    pub fn new(rng: StdRng, txn_factory: TransactionFactory, gas_price: u64) -> Self {
        Self {
            rng,
            txn_factory,
            package_handler: Arc::new(RwLock::new(PackageHandler::new())),
            gas_price,
        }
    }
}

#[async_trait]
impl TransactionGeneratorCreator for PublishPackageCreator {
    async fn create_transaction_generator(&self) -> Box<dyn TransactionGenerator> {
        Box::new(PublishPackageGenerator::new(
            self.rng.clone(),
            self.package_handler.clone(),
            self.txn_factory.clone(),
            self.gas_price,
        ))
    }
}

// ================= CallDifferentModules ===========

use super::publishing::{module_simple::EntryPoints, publish_util::Package};
use aptos_logger::{error, info};
use aptos_rest_client::Client as RestClient;
use futures::future::join_all;

#[allow(dead_code)]
pub struct CallDifferentModulesGenerator {
    txn_factory: TransactionFactory,
    packages: Arc<HashMap<AccountAddress, Package>>,
}

impl CallDifferentModulesGenerator {
    pub fn new(
        txn_factory: TransactionFactory,
        packages: Arc<HashMap<AccountAddress, Package>>,
    ) -> Self {
        Self {
            txn_factory,
            packages,
        }
    }
}

#[async_trait]
impl TransactionGenerator for CallDifferentModulesGenerator {
    fn generate_transactions(
        &mut self,
        accounts: Vec<&mut LocalAccount>,
        transactions_per_account: usize,
    ) -> Vec<SignedTransaction> {
        let mut requests = Vec::with_capacity(accounts.len() * transactions_per_account);
        for account in accounts {
            let package = self.packages.get(&account.address()).unwrap_or_else(|| {
                panic!(
                    "{} : {:?}",
                    account.address(),
                    self.packages.keys().cloned().collect::<Vec<_>>()
                )
            });
            for _ in 0..transactions_per_account {
                let request = package.use_specific_transaction(
                    EntryPoints::Nop,
                    account,
                    &self.txn_factory,
                    None,
                    None,
                );
                requests.push(request);
            }
        }
        requests
    }
}

pub struct CallDifferentModulesCreator {
    txn_factory: TransactionFactory,
    packages: Arc<HashMap<AccountAddress, Package>>,
}

impl CallDifferentModulesCreator {
    pub async fn new(
        mut rng: StdRng,
        txn_factory: TransactionFactory,
        accounts: &mut [LocalAccount],
        client: RestClient,
        max_submit_batch_size: usize,
    ) -> Self {
        let mut requests = Vec::with_capacity(accounts.len());
        let mut package_handler = PackageHandler::new();
        let mut packages = HashMap::new();
        for account in accounts {
            let package = package_handler.pick_package(&mut rng, account);
            let txn = package.publish_transaction(account, &txn_factory);
            requests.push(txn);
            packages.insert(account.address(), package);
        }
        info!("Publishing {} packages", requests.len());
        join_all(
            requests
                .chunks(max_submit_batch_size)
                .map(|reqs| async {
                    match client.submit_batch_bcs(reqs).await {
                        Err(e) => {
                            error!(
                                "[{:?}] CallDifferentModulesCreator: Failed to submit batch request: {:?}",
                                client.path_prefix_string(),
                                e
                            );
                        }
                        Ok(v) => {
                            let failures = v.into_inner().transaction_failures;
                            if !failures.is_empty() {
                                error!(
                                    "[{:?}] CallDifferentModulesCreator: Failed to submit part of the batch request: {:?}",
                                    client.path_prefix_string(),
                                    failures
                                );
                            }
                        }
                    }
                }),
        )
        .await;

        join_all(
            requests
                .iter()
                .map(|req| client.wait_for_signed_transaction_bcs(req)),
        )
        .await;

        info!("Done publishing {} packages", requests.len());

        Self {
            txn_factory,
            packages: Arc::new(packages),
        }
    }
}

#[async_trait]
impl TransactionGeneratorCreator for CallDifferentModulesCreator {
    async fn create_transaction_generator(&self) -> Box<dyn TransactionGenerator> {
        Box::new(CallDifferentModulesGenerator::new(
            self.txn_factory.clone(),
            self.packages.clone(),
        ))
    }
}
