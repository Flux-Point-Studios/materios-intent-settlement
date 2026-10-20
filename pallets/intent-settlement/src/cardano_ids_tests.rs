//! Settlement binds the Cardano network that genesis stores in `CardanoIds`:
//! every voucher digest commits to its network magic and Aegis policy hash,
//! and all settlement and expiry evidence must name its Shelley genesis.

use super::*;
use crate::migrations::SeedCardanoIds;
use crate::pallet::{CardanoIds, Error, GenesisConfig, SettlementStorageVersion};
use frame_support::traits::{BuildGenesisConfig, OnRuntimeUpgrade};

/// Cardano preprod, as the preprod runtime has been binding it: no Aegis
/// policy deployed.
const PREPROD: CardanoIdentity = CardanoIdentity {
    network_magic: 1,
    mainchain_genesis_hash: hex_literal::hex!(
        "162d29c4e1cf6b8a84f2d692e67a3ac6bc7851bc3e6e4afe64d15778bed8bd86"
    ),
    aegis_policy_v1_script_hash: [0; 28],
};

const MAINNET: CardanoIdentity = CardanoIdentity {
    network_magic: CARDANO_MAINNET_NETWORK_MAGIC,
    mainchain_genesis_hash: CARDANO_MAINNET_SHELLEY_GENESIS_HASH,
    aegis_policy_v1_script_hash: [0x5a; 28],
};

fn genesis(cardano_ids: Option<CardanoIdentity>) -> GenesisConfig<Test> {
    GenesisConfig::<Test> {
        cardano_ids,
        ..Default::default()
    }
}

/// Cardano mainnet's ids are those its published environment gives
/// (book.world.dev.cardano.org/environments/mainnet): the `networkMagic` of
/// its `shelley-genesis.json`, and that file's blake2b-256, which its
/// `config.json` publishes as `ShelleyGenesisHash`.
#[test]
fn cardano_mainnets_ids_are_those_of_its_published_shelley_genesis() {
    let shelley = include_bytes!("../tests/fixtures/cardano-mainnet-shelley-genesis.json");
    let config: serde_json::Value = serde_json::from_str(include_str!(
        "../tests/fixtures/cardano-mainnet-config.json"
    ))
    .expect("the published config is JSON");
    let published: serde_json::Value =
        serde_json::from_slice(shelley).expect("the published Shelley genesis is JSON");
    assert_eq!(
        published["networkMagic"],
        serde_json::json!(CARDANO_MAINNET_NETWORK_MAGIC)
    );
    assert_eq!(
        sp_core::hashing::blake2_256(shelley),
        CARDANO_MAINNET_SHELLEY_GENESIS_HASH
    );
    assert_eq!(
        config["ShelleyGenesisHash"],
        serde_json::json!(sp_core::hexdisplay::HexDisplay::from(
            &CARDANO_MAINNET_SHELLEY_GENESIS_HASH
        )
        .to_string())
    );
}

#[test]
fn genesis_stores_the_cardano_network_it_names_at_the_current_storage_version() {
    for ids in [PREPROD, MAINNET] {
        let config = genesis(Some(ids));
        assert_eq!(config.ensure_cardano_ids(), Ok(()));
        sp_io::TestExternalities::default().execute_with(|| {
            config.build();
            assert_eq!(CardanoIds::<Test>::get(), Some(ids));
            assert_eq!(SettlementStorageVersion::<Test>::get(), 5);
            assert_eq!(crate::SETTLEMENT_STORAGE_VERSION, 5);
        });
    }
}

/// FRAME builds every pallet's default genesis in its own tests, so the
/// default stores nothing rather than refusing; the runtime's genesis
/// builder refuses it through `ensure_cardano_ids`.
#[test]
fn a_genesis_naming_no_cardano_network_stores_none_and_the_genesis_builder_refuses_it() {
    let config = genesis(None);
    sp_io::TestExternalities::default().execute_with(|| {
        config.build();
        assert_eq!(CardanoIds::<Test>::get(), None);
    });
    let refusal = config.ensure_cardano_ids().expect_err("no Cardano network");
    assert!(refusal.contains("names no Cardano network"), "{refusal}");
}

/// A zero network magic or Shelley genesis hash names no Cardano network.
/// Cardano mainnet's magic and Shelley genesis hash come together, with the
/// Aegis policy the launch deploys; a test network may have none deployed.
#[test]
fn the_genesis_builder_refuses_ids_naming_no_cardano_network_or_mainnet_in_part() {
    for (case, ids, reason) in [
        (
            "network magic 0",
            CardanoIdentity {
                network_magic: 0,
                ..PREPROD
            },
            "network magic 0",
        ),
        (
            "an all-zero Shelley genesis hash",
            CardanoIdentity {
                mainchain_genesis_hash: [0; 32],
                ..PREPROD
            },
            "all-zero Shelley genesis hash",
        ),
        (
            "mainnet's magic with preprod's Shelley genesis",
            CardanoIdentity {
                mainchain_genesis_hash: PREPROD.mainchain_genesis_hash,
                ..MAINNET
            },
            "Cardano mainnet's network magic and Shelley genesis hash",
        ),
        (
            "mainnet's Shelley genesis with preprod's magic",
            CardanoIdentity {
                network_magic: 1,
                ..MAINNET
            },
            "Cardano mainnet's network magic and Shelley genesis hash",
        ),
        (
            "mainnet with no Aegis policy",
            CardanoIdentity {
                aegis_policy_v1_script_hash: [0; 28],
                ..MAINNET
            },
            "no aegis_policy_v1 script hash",
        ),
    ] {
        let refusal = genesis(Some(ids)).ensure_cardano_ids().expect_err(case);
        assert!(refusal.contains(reason), "{case}: {refusal}");
        let built = std::panic::catch_unwind(|| {
            sp_io::TestExternalities::default().execute_with(|| genesis(Some(ids)).build())
        });
        assert!(built.is_err(), "{case}: genesis built");
    }
}

/// Every call that computes a voucher digest or checks Cardano evidence
/// refuses with `CardanoIdsMissing` while the chain stores no Cardano
/// network, and changes nothing.
#[test]
fn every_settlement_call_refuses_while_no_cardano_network_is_stored() {
    let missing: sp_runtime::DispatchError = Error::<Test>::CardanoIdsMissing.into();
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let claim_id = H256::repeat_byte(0x31);
        let bfpr = good_fairness_proof(iid, 1_000_000);
        let voucher = good_voucher(claim_id, &bfpr, 1_000_000);
        CardanoIds::<Test>::kill();
        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                claim_id,
                iid,
                voucher,
                bfpr,
                mock_voucher_sigs()
            )
            .map_err(|refused| refused.error),
            missing
        );
    });
    new_test_ext().execute_with(|| {
        let iids = submit_n_attested(2);
        let entries: BoundedVec<RequestVoucherEntry, MaxVoucherBatch> =
            BoundedVec::try_from(build_voucher_entries(&iids, 1_000_000)).unwrap();
        CardanoIds::<Test>::kill();
        assert_noop!(
            IntentSettlement::request_batch_vouchers(
                RuntimeOrigin::signed(1),
                entries,
                rvbn_sigs()
            )
            .map_err(|refused| refused.error),
            missing
        );
    });
    new_test_ext().execute_with(|| {
        let (claim_id, _, voucher) = vouchered_claim_with_voucher(0x32, 100_000);
        let evidence = settled_evidence_for(&voucher, 15, 1);
        CardanoIds::<Test>::kill();
        assert_noop!(
            IntentSettlement::request_settle(
                RuntimeOrigin::signed(1),
                claim_id,
                evidence.cardano_tx_hash,
                false,
                evidence,
                1
            ),
            missing
        );
        let entries: BoundedVec<SettleAttestedBatchEntry, MaxSettleBatch> =
            BoundedVec::try_from(vec![SettleAttestedBatchEntry {
                claim_id,
                settled_direct: false,
                evidence,
            }])
            .unwrap();
        assert_noop!(
            IntentSettlement::request_batch_settle(RuntimeOrigin::signed(1), entries, 1),
            missing
        );
    });
    new_test_ext().execute_with(|| {
        let (claim_id, _, voucher) = vouchered_claim_with_voucher(0x33, 100_000);
        let evidence = settled_evidence_for(&voucher, 15, 1);
        assert_ok!(IntentSettlement::request_settle(
            RuntimeOrigin::signed(1),
            claim_id,
            evidence.cardano_tx_hash,
            false,
            evidence,
            1
        ));
        CardanoIds::<Test>::kill();
        assert_noop!(
            IntentSettlement::attest_settle(RuntimeOrigin::signed(1), claim_id, mock_settle_sigs())
                .map_err(|refused| refused.error),
            missing
        );
        assert_noop!(
            IntentSettlement::attest_batch_settle(
                RuntimeOrigin::signed(1),
                BoundedVec::try_from(vec![claim_id]).unwrap(),
                mock_settle_sigs()
            )
            .map_err(|refused| refused.error),
            missing
        );
        let superseding = SettlementEvidence {
            observed_slot: 2,
            ..evidence
        };
        assert_noop!(
            IntentSettlement::supersede_settlement_request(
                RuntimeOrigin::signed(1),
                claim_id,
                false,
                superseding,
                mock_settle_sigs()
            )
            .map_err(|refused| refused.error),
            missing
        );
    });
    new_test_ext().execute_with(|| {
        let (intent_id, product_id) = attested_buy_policy_with_policy_id(0x34, 50_000);
        let evidence = good_expiry_evidence_for_buy(product_id, 15, 1);
        assert_ok!(IntentSettlement::request_expire_policy(
            RuntimeOrigin::signed(1),
            intent_id,
            evidence.cardano_tx_hash,
            evidence
        ));
        CardanoIds::<Test>::kill();
        assert_noop!(
            IntentSettlement::attest_expire_policy(
                RuntimeOrigin::signed(1),
                intent_id,
                mock_settle_sigs()
            )
            .map_err(|refused| refused.error),
            missing
        );
        let (other, other_product) = attested_buy_policy_with_policy_id(0x35, 50_000);
        let evidence = good_expiry_evidence_for_buy(other_product, 15, 1);
        assert_noop!(
            IntentSettlement::request_expire_policy(
                RuntimeOrigin::signed(1),
                other,
                evidence.cardano_tx_hash,
                evidence
            ),
            missing
        );
    });
}

/// Settlement and expiry evidence must name the Shelley genesis the chain
/// stores, whatever any other source names.
#[test]
fn evidence_must_name_the_stored_shelley_genesis() {
    let stored = CardanoIdentity {
        mainchain_genesis_hash: [0x77; 32],
        ..TEST_CARDANO_IDS
    };
    new_test_ext().execute_with(|| {
        CardanoIds::<Test>::put(stored);
        let (claim_id, _, voucher) = vouchered_claim_with_voucher(0x36, 100_000);
        let unstored = settled_evidence_for(&voucher, 15, 1);
        assert_noop!(
            IntentSettlement::request_settle(
                RuntimeOrigin::signed(1),
                claim_id,
                unstored.cardano_tx_hash,
                false,
                unstored,
                1
            ),
            Error::<Test>::WrongMainchainGenesis
        );
        let named = SettlementEvidence {
            mainchain_genesis_hash: stored.mainchain_genesis_hash,
            ..unstored
        };
        assert_ok!(IntentSettlement::request_settle(
            RuntimeOrigin::signed(1),
            claim_id,
            named.cardano_tx_hash,
            false,
            named,
            1
        ));

        let (intent_id, product_id) = attested_buy_policy_with_policy_id(0x37, 50_000);
        let unstored = good_expiry_evidence_for_buy(product_id, 15, 1);
        assert_noop!(
            IntentSettlement::request_expire_policy(
                RuntimeOrigin::signed(1),
                intent_id,
                unstored.cardano_tx_hash,
                unstored
            ),
            Error::<Test>::WrongMainchainGenesis
        );
        let named = ExpiryEvidence {
            mainchain_genesis_hash: stored.mainchain_genesis_hash,
            ..unstored
        };
        assert_ok!(IntentSettlement::request_expire_policy(
            RuntimeOrigin::signed(1),
            intent_id,
            named.cardano_tx_hash,
            named
        ));
    });
}

/// `request_expire_policy` now reads the stored Cardano ids, so it charges
/// its measured weight rather than a fixed figure.
#[test]
fn request_expire_policy_charges_its_configured_weight() {
    use crate::weights::WeightInfo;
    use frame_support::dispatch::{DispatchClass, GetDispatchInfo, Pays};
    let info = crate::Call::<Test>::request_expire_policy {
        intent_id: H256::zero(),
        cardano_tx_hash: [0; 32],
        attestation_evidence: good_expiry_evidence_for_buy(H256::zero(), 15, 1),
    }
    .get_dispatch_info();
    assert_eq!(info.weight, BondWeights::request_expire_policy());
    assert_eq!(info.class, DispatchClass::Operational);
    assert_eq!(info.pays_fee, Pays::Yes);
}

parameter_types! {
    pub SeedPreprod: Option<CardanoIdentity> = Some(PREPROD);
    pub SeedNone: Option<CardanoIdentity> = None;
}

/// Every key under the settlement pallet's prefix, with its value.
fn settlement_storage() -> Vec<(Vec<u8>, Vec<u8>)> {
    let prefix = sp_io::hashing::twox_128(b"IntentSettlement");
    let mut entries = Vec::new();
    let mut cursor = prefix.to_vec();
    while let Some(key) = sp_io::storage::next_key(&cursor) {
        if !key.starts_with(&prefix) {
            break;
        }
        entries.push((key.clone(), sp_io::storage::get(&key).unwrap().to_vec()));
        cursor = key;
    }
    entries
}

/// A version-4 chain started before genesis stored its Cardano ids. The
/// upgrade stores the ids its settlement has been binding and moves it to
/// version 5, once.
#[test]
fn seeding_stores_a_version_4_chains_ids_and_moves_it_to_version_5_once() {
    new_test_ext().execute_with(|| {
        CardanoIds::<Test>::kill();
        SettlementStorageVersion::<Test>::put(4);
        let before = settlement_storage();

        SeedCardanoIds::<Test, SeedPreprod>::on_runtime_upgrade();

        assert_eq!(CardanoIds::<Test>::get(), Some(PREPROD));
        assert_eq!(SettlementStorageVersion::<Test>::get(), 5);
        let seeded = settlement_storage();
        let touched = [
            SettlementStorageVersion::<Test>::hashed_key().to_vec(),
            CardanoIds::<Test>::hashed_key().to_vec(),
        ];
        let untouched = |entries: &[(Vec<u8>, Vec<u8>)]| {
            entries
                .iter()
                .filter(|(key, _)| !touched.contains(key))
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(untouched(&seeded), untouched(&before));

        SeedCardanoIds::<Test, SeedPreprod>::on_runtime_upgrade();
        assert_eq!(settlement_storage(), seeded);
    });
}

/// A version-4 chain whose ids the runtime does not know keeps version 4 and
/// stores none, so settlement refuses rather than bind another network.
#[test]
fn seeding_leaves_a_chain_whose_ids_the_runtime_does_not_know_unseeded() {
    new_test_ext().execute_with(|| {
        CardanoIds::<Test>::kill();
        SettlementStorageVersion::<Test>::put(4);
        let before = settlement_storage();

        SeedCardanoIds::<Test, SeedNone>::on_runtime_upgrade();

        assert_eq!(settlement_storage(), before);
    });
}

/// Seeding moves only version 4: a chain still migrating to it, or whose
/// genesis stored its ids, is left as it is.
#[test]
fn seeding_leaves_every_other_storage_version_alone() {
    for version in [3, 5] {
        new_test_ext().execute_with(|| {
            SettlementStorageVersion::<Test>::put(version);
            if version == 3 {
                CardanoIds::<Test>::kill();
            }
            let before = settlement_storage();

            SeedCardanoIds::<Test, SeedPreprod>::on_runtime_upgrade();

            assert_eq!(settlement_storage(), before, "version {version}");
        });
    }
}

#[cfg(feature = "try-runtime")]
#[test]
fn try_state_holds_version_5_to_valid_cardano_ids() {
    use frame_support::traits::Hooks;
    new_test_ext().execute_with(|| {
        SettlementStorageVersion::<Test>::put(5);
        assert_ok!(IntentSettlement::try_state(1));
        CardanoIds::<Test>::put(CardanoIdentity {
            network_magic: 0,
            ..TEST_CARDANO_IDS
        });
        assert!(IntentSettlement::try_state(1).is_err());
        CardanoIds::<Test>::kill();
        assert!(IntentSettlement::try_state(1).is_err());
    });
}

#[cfg(feature = "try-runtime")]
#[test]
fn seeding_passes_its_upgrade_checks() {
    new_test_ext().execute_with(|| {
        CardanoIds::<Test>::kill();
        SettlementStorageVersion::<Test>::put(4);
        assert_ok!(SeedCardanoIds::<Test, SeedPreprod>::try_on_runtime_upgrade(
            true
        ));
        assert_eq!(CardanoIds::<Test>::get(), Some(PREPROD));
        assert_ok!(SeedCardanoIds::<Test, SeedPreprod>::try_on_runtime_upgrade(
            true
        ));
    });
    new_test_ext().execute_with(|| {
        CardanoIds::<Test>::kill();
        SettlementStorageVersion::<Test>::put(4);
        assert_ok!(SeedCardanoIds::<Test, SeedNone>::try_on_runtime_upgrade(
            true
        ));
        assert_eq!(CardanoIds::<Test>::get(), None);
    });
}
