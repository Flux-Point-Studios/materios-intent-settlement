//! Settlement binds the Cardano network that genesis stores in `CardanoIds`:
//! every voucher digest commits to its network magic and Aegis policy hash,
//! and all settlement and expiry evidence must name its Shelley genesis.

use super::*;
use crate::migrations::SeedCardanoIds;
use crate::pallet::{CardanoIds, Error, Event, GenesisConfig, SettlementStorageVersion};
use frame_support::traits::{BuildGenesisConfig, OnRuntimeUpgrade};
use parity_scale_codec::Decode;
use sp_runtime::{DispatchError, DispatchError::BadOrigin};

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

/// Cardano mainnet before Root binds the Aegis policy, which is applied to
/// the chain's own genesis hash and so cannot be named in that genesis.
const UNBOUND_MAINNET: CardanoIdentity = CardanoIdentity {
    aegis_policy_v1_script_hash: [0; 28],
    ..MAINNET
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
    for ids in [PREPROD, MAINNET, UNBOUND_MAINNET] {
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

/// A zero network magic or Shelley genesis hash names no Cardano network,
/// and Cardano mainnet's magic and Shelley genesis hash come together.
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
    TestCardanoIdsToSeed::set(Some(PREPROD));
    new_test_ext().execute_with(|| {
        CardanoIds::<Test>::kill();
        SettlementStorageVersion::<Test>::put(4);
        let before = settlement_storage();

        SeedCardanoIds::<Test>::on_runtime_upgrade();

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

        SeedCardanoIds::<Test>::on_runtime_upgrade();
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

        SeedCardanoIds::<Test>::on_runtime_upgrade();

        assert_eq!(settlement_storage(), before);
    });
}

/// Seeding moves only version 4: a chain still migrating to it, or whose
/// genesis stored its ids, is left as it is.
#[test]
fn seeding_leaves_every_other_storage_version_alone() {
    TestCardanoIdsToSeed::set(Some(PREPROD));
    for version in [3, 5] {
        new_test_ext().execute_with(|| {
            SettlementStorageVersion::<Test>::put(version);
            if version == 3 {
                CardanoIds::<Test>::kill();
            }
            let before = settlement_storage();

            SeedCardanoIds::<Test>::on_runtime_upgrade();

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
        CardanoIds::<Test>::put(UNBOUND_MAINNET);
        assert_ok!(IntentSettlement::try_state(1));
    });
}

#[cfg(feature = "try-runtime")]
#[test]
fn seeding_passes_its_upgrade_checks() {
    for to_seed in [Some(PREPROD), None] {
        TestCardanoIdsToSeed::set(to_seed);
        new_test_ext().execute_with(|| {
            CardanoIds::<Test>::kill();
            SettlementStorageVersion::<Test>::put(4);
            assert_ok!(SeedCardanoIds::<Test>::try_on_runtime_upgrade(true));
            assert_eq!(CardanoIds::<Test>::get(), to_seed);
            assert_ok!(SeedCardanoIds::<Test>::try_on_runtime_upgrade(true));
        });
    }
}

/// What the pallet's metadata reports for its constant `name`, read in the
/// current state: the constant's type and its SCALE-encoded value.
fn metadata_constant(name: &str) -> (scale_info::MetaType, Vec<u8>) {
    let constant = IntentSettlement::pallet_constants_metadata()
        .into_iter()
        .find(|constant| constant.name == name)
        .unwrap_or_else(|| panic!("the metadata declares no IntentSettlement.{name}"));
    (constant.ty, constant.value)
}

/// The network magic and Aegis policy a committee daemon rebuilds every
/// voucher digest from: the metadata constants `NetworkMagic`, a u32, and
/// `AegisPolicyV1ScriptHash`, 28 bytes, the names and types the runtime's
/// configuration gave them before genesis stored the ids.
fn reported_voucher_ids() -> (u32, [u8; 28]) {
    let (magic_type, magic) = metadata_constant("NetworkMagic");
    let (aegis_type, aegis) = metadata_constant("AegisPolicyV1ScriptHash");
    assert_eq!(magic_type, scale_info::meta_type::<u32>());
    assert_eq!(aegis_type, scale_info::meta_type::<[u8; 28]>());
    (
        u32::decode(&mut &magic[..]).expect("a u32"),
        <[u8; 28]>::decode(&mut &aegis[..]).expect("28 bytes"),
    )
}

#[test]
fn metadata_reports_the_stored_network_magic_and_aegis_policy() {
    new_test_ext().execute_with(|| {
        assert_eq!(
            reported_voucher_ids(),
            (
                TEST_CARDANO_IDS.network_magic,
                TEST_CARDANO_IDS.aegis_policy_v1_script_hash
            )
        );
    });
}

/// A client reads metadata in the state of the block that sets new code,
/// before the next block's upgrade seeds the ids, and keeps it for the whole
/// spec version. Read there, the metadata reports the ids the seed stores;
/// with none to seed, or on a chain the seed leaves alone, it reports zero.
#[test]
fn metadata_read_before_the_seed_reports_the_ids_it_stores() {
    let seeded = CardanoIdentity {
        network_magic: 2,
        mainchain_genesis_hash: [0x66; 32],
        aegis_policy_v1_script_hash: [0x44; 28],
    };
    for (version, to_seed, reported) in [
        (4, Some(seeded), (2, [0x44; 28])),
        (4, None, (0, [0; 28])),
        (3, Some(seeded), (0, [0; 28])),
    ] {
        TestCardanoIdsToSeed::set(to_seed);
        new_test_ext().execute_with(|| {
            CardanoIds::<Test>::kill();
            SettlementStorageVersion::<Test>::put(version);
            assert_eq!(
                reported_voucher_ids(),
                reported,
                "version {version}, {to_seed:?}"
            );
            SeedCardanoIds::<Test>::on_runtime_upgrade();
            assert_eq!(
                reported_voucher_ids(),
                reported,
                "version {version}, {to_seed:?}"
            );
        });
    }
}

/// The Aegis policy a mainnet launch deploys is applied to the chain's own
/// genesis hash, so a mainnet genesis may leave it to be bound after launch.
#[test]
fn a_mainnet_genesis_may_leave_its_aegis_policy_unbound() {
    let config = genesis(Some(UNBOUND_MAINNET));
    assert_eq!(config.ensure_cardano_ids(), Ok(()));
    sp_io::TestExternalities::default().execute_with(|| {
        config.build();
        assert_eq!(CardanoIds::<Test>::get(), Some(UNBOUND_MAINNET));
    });
}

/// No mainnet Aegis validator accepts a voucher bound to no policy, so on
/// Cardano mainnet every call that computes a voucher digest or checks
/// Cardano evidence refuses until Root binds one, and goes through after.
#[test]
fn settlement_on_cardano_mainnet_refuses_until_an_aegis_policy_is_bound() {
    let unbound: DispatchError = Error::<Test>::AegisPolicyV1Unbound.into();
    new_test_ext().execute_with(|| {
        let iid = attested_intent();
        let (claim_id, _, voucher) = vouchered_claim_with_voucher(0x38, 100_000);
        let (intent_id, product_id) = attested_buy_policy_with_policy_id(0x39, 50_000);
        let unvouchered = H256::repeat_byte(0x3a);
        let bfpr = good_fairness_proof(iid, 1_000_000);
        let new_voucher = good_voucher(unvouchered, &bfpr, 1_000_000);
        let settlement = SettlementEvidence {
            mainchain_genesis_hash: CARDANO_MAINNET_SHELLEY_GENESIS_HASH,
            ..settled_evidence_for(&voucher, 15, 1)
        };
        let expiry = ExpiryEvidence {
            mainchain_genesis_hash: CARDANO_MAINNET_SHELLEY_GENESIS_HASH,
            ..good_expiry_evidence_for_buy(product_id, 15, 1)
        };
        CardanoIds::<Test>::put(UNBOUND_MAINNET);

        assert_noop!(
            IntentSettlement::request_voucher(
                RuntimeOrigin::signed(1),
                unvouchered,
                iid,
                new_voucher.clone(),
                bfpr.clone(),
                mock_voucher_sigs()
            )
            .map_err(|refused| refused.error),
            unbound
        );
        assert_noop!(
            IntentSettlement::request_settle(
                RuntimeOrigin::signed(1),
                claim_id,
                settlement.cardano_tx_hash,
                false,
                settlement,
                1
            ),
            unbound
        );
        assert_noop!(
            IntentSettlement::request_expire_policy(
                RuntimeOrigin::signed(1),
                intent_id,
                expiry.cardano_tx_hash,
                expiry
            ),
            unbound
        );

        assert_ok!(IntentSettlement::bind_aegis_policy_v1(
            RuntimeOrigin::root(),
            MAINNET.aegis_policy_v1_script_hash
        ));
        assert_ok!(IntentSettlement::request_voucher(
            RuntimeOrigin::signed(1),
            unvouchered,
            iid,
            new_voucher,
            bfpr,
            mock_voucher_sigs()
        ));
        assert_ok!(IntentSettlement::request_settle(
            RuntimeOrigin::signed(1),
            claim_id,
            settlement.cardano_tx_hash,
            false,
            settlement,
            1
        ));
        assert_ok!(IntentSettlement::request_expire_policy(
            RuntimeOrigin::signed(1),
            intent_id,
            expiry.cardano_tx_hash,
            expiry
        ));
    });
}

/// Root binds the `aegis_policy_v1` script hash once, on a chain that names
/// its Cardano network and binds none yet; the metadata reports it from then
/// on.
#[test]
fn root_binds_an_aegis_policy_once() {
    let bound = MAINNET.aegis_policy_v1_script_hash;
    new_test_ext().execute_with(|| {
        CardanoIds::<Test>::put(UNBOUND_MAINNET);
        assert_noop!(
            IntentSettlement::bind_aegis_policy_v1(RuntimeOrigin::signed(1), bound),
            BadOrigin
        );
        assert_noop!(
            IntentSettlement::bind_aegis_policy_v1(RuntimeOrigin::root(), [0; 28]),
            Error::<Test>::AegisPolicyV1Unbound
        );
        assert_eq!(
            reported_voucher_ids(),
            (CARDANO_MAINNET_NETWORK_MAGIC, [0; 28])
        );

        assert_ok!(IntentSettlement::bind_aegis_policy_v1(
            RuntimeOrigin::root(),
            bound
        ));
        assert_eq!(CardanoIds::<Test>::get(), Some(MAINNET));
        System::assert_last_event(Event::AegisPolicyV1Bound { script_hash: bound }.into());
        assert_eq!(
            reported_voucher_ids(),
            (CARDANO_MAINNET_NETWORK_MAGIC, bound)
        );

        for again in [bound, [0x5b; 28]] {
            assert_noop!(
                IntentSettlement::bind_aegis_policy_v1(RuntimeOrigin::root(), again),
                Error::<Test>::AegisPolicyV1AlreadyBound
            );
        }
        CardanoIds::<Test>::kill();
        assert_noop!(
            IntentSettlement::bind_aegis_policy_v1(RuntimeOrigin::root(), bound),
            Error::<Test>::CardanoIdsMissing
        );
    });
}

#[test]
fn binding_an_aegis_policy_charges_its_configured_weight() {
    use crate::weights::WeightInfo;
    use frame_support::dispatch::{DispatchClass, GetDispatchInfo, Pays};
    let info = crate::Call::<Test>::bind_aegis_policy_v1 {
        script_hash: [0x5a; 28],
    }
    .get_dispatch_info();
    assert_eq!(info.weight, BondWeights::bind_aegis_policy_v1());
    assert_eq!(info.class, DispatchClass::Operational);
    assert_eq!(info.pays_fee, Pays::No);
}
