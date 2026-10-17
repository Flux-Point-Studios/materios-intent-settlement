use super::*;
use crate::pallet::*;

fn genesis_ext() -> sp_io::TestExternalities {
    RuntimeGenesisConfig {
        balances: pallet_balances::GenesisConfig::<Test> {
            balances: vec![(ALICE, 10_000), (BOB, 10_000)],
        },
        intent_settlement: GenesisConfig::<Test> {
            pool_utilization: PoolUtilizationParams {
                target_bps: 5_000,
                cap_bps: 7_500,
                total_nav_ada: 10_000_000,
                outstanding_coverage_ada: 0,
            },
            ..Default::default()
        },
        ..Default::default()
    }
    .build_storage()
    .expect("valid genesis")
    .into()
}

#[test]
fn genesis_safety_closes_single_settlement_at_block_zero() {
    genesis_ext().execute_with(|| {
        let (cid, _, _) = vouchered_claim_with_voucher(0x11, 1_000);
        assert_noop!(
            IntentSettlement::settle_claim(
                RuntimeOrigin::signed(1),
                cid,
                [0x12; 32],
                false,
                mock_settle_sigs()
            )
            .map_err(|error| error.error),
            Error::<Test>::DeprecatedExtrinsic
        );
    });
}

#[test]
fn genesis_safety_closes_batch_settlement_at_block_zero() {
    genesis_ext().execute_with(|| {
        let (cid, _, _) = vouchered_claim_with_voucher(0x11, 1_000);
        let entries = vec![SettleBatchEntry {
            claim_id: cid,
            cardano_tx_hash: [0x12; 32],
            settled_direct: false,
        }];
        assert_noop!(
            IntentSettlement::settle_batch_atomic(
                RuntimeOrigin::signed(1),
                entries.try_into().expect("one entry"),
                mock_settle_sigs()
            )
            .map_err(|error| error.error),
            Error::<Test>::DeprecatedExtrinsic
        );
    });
}

#[test]
fn genesis_safety_closes_policy_expiry_at_block_zero() {
    genesis_ext().execute_with(|| {
        let (_, iid, _) = vouchered_claim_with_voucher(0x11, 1_000);
        assert_noop!(
            IntentSettlement::expire_policy_mirror(RuntimeOrigin::signed(1), iid),
            Error::<Test>::DeprecatedExtrinsic
        );
    });
}

#[test]
fn genesis_safety_upgrade_preserves_post_genesis_audit_state() {
    genesis_ext().execute_with(|| {
        System::set_block_number(1);
        let (cid, iid, voucher) = vouchered_claim_with_voucher(0x11, 1_000);
        let evidence = settled_evidence_for(&voucher, 15, 12_345);
        assert_ok!(IntentSettlement::request_settle(
            RuntimeOrigin::signed(ALICE),
            cid,
            evidence.cardano_tx_hash,
            false,
            evidence,
            1
        ));
        assert_ok!(IntentSettlement::attest_settle(
            RuntimeOrigin::signed(1),
            cid,
            mock_settle_sigs()
        )
        .map_err(|error| error.error));
        let (_, expired_iid, _) = vouchered_claim_with_voucher(0x12, 1_000);
        Intents::<Test>::mutate(expired_iid, |i| {
            i.as_mut().expect("intent").status = IntentStatus::Expired
        });
        let before = sp_io::storage::root(sp_runtime::StateVersion::V1);
        <IntentSettlement as frame_support::traits::OnRuntimeUpgrade>::on_runtime_upgrade();
        assert!(
            !PreAuditSettlement::<Test>::get(cid),
            "STCA settlement must retain its audit status"
        );
        assert!(!PreAuditExpiry::<Test>::get(expired_iid));
        assert_eq!(SettlementStorageVersion::<Test>::get(), crate::SETTLEMENT_STORAGE_VERSION);
        assert_eq!(StcaCutoverBlock::<Test>::get(), 0);
        assert_eq!(PolicyExpireCutoverBlock::<Test>::get(), 0);
        assert_eq!(
            Intents::<Test>::get(iid).expect("intent").status,
            IntentStatus::Settled
        );
        assert_eq!(sp_io::storage::root(sp_runtime::StateVersion::V1), before);
    });
}

#[test]
fn genesis_safety_expired_junk_request_can_be_replaced_and_attested() {
    new_test_ext().execute_with(|| {
        let (cid, _, voucher) = vouchered_claim_with_voucher(0x21, 1_000);
        let mut evidence = settled_evidence_for(&voucher, 15, 12_345);
        assert_ok!(IntentSettlement::request_settle(
            RuntimeOrigin::signed(BOB),
            cid,
            evidence.cardano_tx_hash,
            false,
            evidence,
            1
        ));
        System::set_block_number(1 + TestSettlementRequestTtl::get() as u64);
        evidence.cardano_tx_hash = [0x33; 32];
        assert_noop!(
            IntentSettlement::request_settle(
                RuntimeOrigin::signed(ALICE),
                cid,
                evidence.cardano_tx_hash,
                false,
                evidence,
                1
            ),
            Error::<Test>::SettlementRequestAlreadyExists
        );
        System::set_block_number(System::block_number() + 1);
        assert_ok!(IntentSettlement::request_settle(
            RuntimeOrigin::signed(ALICE),
            cid,
            evidence.cardano_tx_hash,
            false,
            evidence,
            1
        ));
        assert_ok!(IntentSettlement::attest_settle(
            RuntimeOrigin::signed(1),
            cid,
            mock_settle_sigs()
        )
        .map_err(|error| error.error));
        assert_eq!(
            Claims::<Test>::get(cid).expect("claim").cardano_tx_hash,
            evidence.cardano_tx_hash
        );
    });
}

#[test]
fn genesis_safety_replacement_refunds_old_bonder_in_single_and_batch_paths() {
    for batch in [false, true] {
        new_test_ext().execute_with(|| {
            let (cid, voucher) = alice_request_and_bond(0x22, 1_000, 500);
            let evidence = settled_evidence_for(&voucher, 15, 12_345);
            let free = Balances::free_balance(ALICE);
            System::set_block_number(2 + TestSettlementRequestTtl::get() as u64);
            if batch {
                assert_ok!(IntentSettlement::request_batch_settle(
                    RuntimeOrigin::signed(BOB),
                    vec![SettleAttestedBatchEntry {
                        claim_id: cid,
                        settled_direct: false,
                        evidence
                    }]
                    .try_into()
                    .expect("one entry"),
                    1
                ));
            } else {
                assert_ok!(IntentSettlement::request_settle(
                    RuntimeOrigin::signed(BOB),
                    cid,
                    evidence.cardano_tx_hash,
                    false,
                    evidence,
                    1
                ));
            }
            assert_eq!(Balances::free_balance(ALICE), free + 500);
            assert_eq!(Balances::reserved_balance(ALICE), 0);
            let request = ClaimSettlementRequests::<Test>::get(cid).expect("replacement");
            assert_eq!(request.requester, BOB);
            assert_eq!(request.bond_amount, 1);
            assert!(!BondedClaimRequester::<Test>::contains_key(cid));
            assert!(!BondedClaimAttestedAt::<Test>::contains_key(cid));
        });
    }
}

#[test]
fn genesis_safety_expired_bond_release_is_permissionless_and_single_use() {
    for caller in [ALICE, BOB] {
        new_test_ext().execute_with(|| {
            let (cid, _) = alice_request_and_bond(0x23, 1_000, 500);
            let free = Balances::free_balance(ALICE);
            System::set_block_number(2 + TestSettlementRequestTtl::get() as u64);
            assert_ok!(IntentSettlement::release_settlement_bond(
                RuntimeOrigin::signed(caller),
                cid
            ));
            assert_eq!(Balances::reserved_balance(ALICE), 0);
            assert_eq!(Balances::free_balance(ALICE), free + 500);
            assert!(!ClaimSettlementRequests::<Test>::contains_key(cid));
            assert_noop!(
                IntentSettlement::release_settlement_bond(RuntimeOrigin::signed(caller), cid),
                Error::<Test>::BondNotReserved
            );
        });
    }
}

#[test]
fn genesis_safety_slash_expires_with_request_before_release() {
    new_test_ext().execute_with(|| {
        let (cid, _) = alice_request_and_bond(0x24, 1_000, 500);
        fund_account(1, 1);
        fund_account(
            TestSettlementTreasuryPalletId::get().into_account_truncating(),
            1,
        );
        System::set_block_number(2 + TestSettlementRequestTtl::get() as u64);
        assert_noop!(
            IntentSettlement::slash_bad_settlement_evidence(
                RuntimeOrigin::signed(1),
                cid,
                FraudProof::TxNotFound,
                mock_settle_sigs()
            )
            .map_err(|error| error.error),
            Error::<Test>::SettlementRequestExpired
        );
        assert_ok!(IntentSettlement::release_settlement_bond(
            RuntimeOrigin::signed(BOB),
            cid
        ));
        assert_noop!(
            IntentSettlement::slash_bad_settlement_evidence(
                RuntimeOrigin::signed(1),
                cid,
                FraudProof::TxNotFound,
                mock_settle_sigs()
            )
            .map_err(|error| error.error),
            Error::<Test>::SettlementRequestMissing
        );
    });
}

#[test]
fn genesis_safety_slash_wins_at_inclusive_ttl_boundary() {
    new_test_ext().execute_with(|| {
        let (cid, _) = alice_request_and_bond(0x25, 1_000, 500);
        fund_account(1, 1);
        fund_account(
            TestSettlementTreasuryPalletId::get().into_account_truncating(),
            1,
        );
        System::set_block_number(1 + TestSettlementRequestTtl::get() as u64);
        assert_noop!(
            IntentSettlement::release_settlement_bond(RuntimeOrigin::signed(BOB), cid),
            Error::<Test>::BondReleaseTooEarly
        );
        assert_ok!(IntentSettlement::slash_bad_settlement_evidence(
            RuntimeOrigin::signed(1),
            cid,
            FraudProof::TxNotFound,
            mock_settle_sigs()
        )
        .map_err(|error| error.error));
        System::set_block_number(System::block_number() + 1);
        assert_noop!(
            IntentSettlement::release_settlement_bond(RuntimeOrigin::signed(BOB), cid),
            Error::<Test>::BondNotReserved
        );
        assert_eq!(Balances::reserved_balance(ALICE), 0);
    });
}

#[test]
fn genesis_safety_threshold_dispatch_weights_scale_for_every_bundle() {
    use frame_support::dispatch::GetDispatchInfo;
    new_test_ext().execute_with(|| {
        let (cid, iid, voucher) = vouchered_claim_with_voucher(0x31, 1_000);
        let calls = |signatures: Vec<(CommitteePubkey, CommitteeSig)>| {
            vec![
                crate::Call::<Test>::credit_deposit {
                    target: ALICE,
                    amount_ada: 1,
                    cardano_tx_hash: [0x44; 32],
                    signatures: signatures.clone(),
                },
                crate::Call::<Test>::settle_claim {
                    claim_id: cid,
                    cardano_tx_hash: [0x44; 32],
                    settled_direct: false,
                    signatures: signatures.clone(),
                },
                crate::Call::<Test>::request_voucher {
                    claim_id: cid,
                    intent_id: iid,
                    voucher: voucher.clone(),
                    fairness_proof: good_fairness_proof(iid, 1_000),
                    signatures: signatures.clone(),
                },
                crate::Call::<Test>::settle_batch_atomic {
                    entries: Default::default(),
                    signatures: signatures.clone(),
                },
                crate::Call::<Test>::attest_batch_intents {
                    intent_ids: Default::default(),
                    signatures: signatures.clone(),
                },
                crate::Call::<Test>::request_batch_vouchers {
                    entries: Default::default(),
                    signatures: signatures.clone(),
                },
                crate::Call::<Test>::attest_settle {
                    claim_id: cid,
                    signatures: signatures.clone(),
                },
                crate::Call::<Test>::attest_batch_settle {
                    claim_ids: Default::default(),
                    signatures: signatures.clone(),
                },
                crate::Call::<Test>::attest_expire_policy {
                    intent_id: iid,
                    signatures: signatures.clone(),
                },
                crate::Call::<Test>::slash_bad_settlement_evidence {
                    claim_id: cid,
                    fraud_proof: FraudProof::TxNotFound,
                    signatures,
                },
            ]
        };
        for (one, two) in calls(vec![mock_sig_for(1)])
            .iter()
            .zip(calls(mock_settle_sigs()))
        {
            assert!(
                two.get_dispatch_info().weight.ref_time()
                    > one.get_dispatch_info().weight.ref_time(),
                "bundle weight must grow: {one:?}"
            );
        }
        let at_limit = calls(vec![mock_sig_for(1); MaxCommittee::get() as usize]);
        let above_limit = calls(vec![mock_sig_for(1); MaxCommittee::get() as usize + 1]);
        for (bounded, oversized) in at_limit.iter().zip(above_limit) {
            assert_eq!(
                bounded.get_dispatch_info().weight,
                oversized.get_dispatch_info().weight
            );
        }
    });
}

#[test]
fn genesis_safety_deposit_replay_performs_zero_verifications() {
    new_test_ext().execute_with(|| {
        assert_ok!(IntentSettlement::credit_deposit(
            RuntimeOrigin::signed(1),
            ALICE,
            100,
            [0x44; 32],
            mock_credit_sigs()
        )
        .map_err(|error| error.error));
        VERIFY_CALLS.with(|count| count.set(0));
        assert_noop!(
            IntentSettlement::credit_deposit(
                RuntimeOrigin::signed(1),
                ALICE,
                100,
                [0x44; 32],
                mock_credit_sigs()
            )
            .map_err(|error| error.error),
            Error::<Test>::DepositAlreadyProcessed
        );
        assert_eq!(VERIFY_CALLS.with(|count| count.get()), 0);
    });
}

#[test]
fn genesis_safety_post_dispatch_refunds_unchecked_signatures_on_error() {
    use frame_support::{dispatch::GetDispatchInfo, traits::UnfilteredDispatchable};
    new_test_ext().execute_with(|| {
        let signatures = vec![mock_sig_for(1), mock_sig_for(9), mock_sig_for(2)];
        let call = crate::Call::<Test>::credit_deposit {
            target: ALICE,
            amount_ada: 1,
            cardano_tx_hash: [0x45; 32],
            signatures,
        };
        let declared = call.get_dispatch_info().weight;
        VERIFY_CALLS.with(|count| count.set(0));
        let failure = call
            .dispatch_bypass_filter(RuntimeOrigin::signed(1))
            .expect_err("non-member second signer");
        assert_eq!(failure.error, Error::<Test>::SignerNotCommitteeMember.into());
        assert_eq!(VERIFY_CALLS.with(|count| count.get()), 0);
        assert!(
            failure
                .post_info
                .actual_weight
                .expect("actual checked work")
                .ref_time()
                < declared.ref_time()
        );
    });
}

#[test]
fn genesis_safety_bundle_prescan_precedes_verification() {
    for (last, error) in [
        (mock_sig_for(1), Error::<Test>::DuplicateSigner),
        (mock_sig_for(9), Error::<Test>::SignerNotCommitteeMember),
    ] {
        new_test_ext().execute_with(|| {
            VERIFY_CALLS.with(|count| count.set(0));
            assert_noop!(
                IntentSettlement::credit_deposit(
                    RuntimeOrigin::signed(1),
                    ALICE,
                    1,
                    [0x46; 32],
                    vec![mock_sig_for(1), mock_sig_for(2), last],
                )
                .map_err(|failure| failure.error),
                error
            );
            assert_eq!(VERIFY_CALLS.with(|count| count.get()), 0);
        });
    }
}

#[test]
fn genesis_safety_batch_replacement_rolls_back_refunds_on_later_failure() {
    new_test_ext().execute_with(|| {
        let (old, voucher) = alice_request_and_bond(0x51, 1_000, 500);
        System::set_block_number(1 + TestSettlementRequestTtl::get() as u64);
        let (fresh, fresh_voucher) = alice_request_and_bond(0x52, 1_000, 600);
        System::set_block_number(System::block_number() + 1);
        let entries = vec![
            SettleAttestedBatchEntry {
                claim_id: old,
                settled_direct: false,
                evidence: settled_evidence_for(&voucher, 15, 123),
            },
            SettleAttestedBatchEntry {
                claim_id: fresh,
                settled_direct: false,
                evidence: settled_evidence_for(&fresh_voucher, 15, 123),
            },
        ];
        assert_noop!(
            IntentSettlement::request_batch_settle(
                RuntimeOrigin::signed(BOB),
                entries.try_into().expect("two entries"),
                1
            ),
            Error::<Test>::SettlementRequestAlreadyExists
        );
        assert_eq!(Balances::reserved_balance(ALICE), 1_100);
        assert_eq!(
            ClaimSettlementRequests::<Test>::get(old)
                .expect("old request")
                .requester,
            ALICE
        );
    });
}

#[test]
fn genesis_safety_attestation_at_ttl_retains_full_release_delay() {
    new_test_ext().execute_with(|| {
        let (cid, _) = alice_request_and_bond(0x53, 1_000, 500);
        let boundary = 1 + TestSettlementRequestTtl::get() as u64;
        System::set_block_number(boundary);
        assert_ok!(IntentSettlement::attest_settle(
            RuntimeOrigin::signed(1),
            cid,
            mock_settle_sigs()
        ));
        System::set_block_number(boundary + 1);
        assert_noop!(
            IntentSettlement::release_settlement_bond(RuntimeOrigin::signed(BOB), cid),
            Error::<Test>::BondReleaseTooEarly
        );
        System::set_block_number(boundary + TestBondReleaseDelayBlocks::get() as u64);
        assert_ok!(IntentSettlement::release_settlement_bond(
            RuntimeOrigin::signed(BOB),
            cid
        ));
        assert_eq!(Balances::reserved_balance(ALICE), 0);
    });
}

#[test]
fn genesis_safety_actual_signature_weight_matches_checked_prefix() {
    use frame_support::{dispatch::GetDispatchInfo, traits::UnfilteredDispatchable};
    let deposit = |signatures| crate::Call::<Test>::credit_deposit {
        target: ALICE,
        amount_ada: 1,
        cardano_tx_hash: [0x61; 32],
        signatures,
    };
    for rejected_at in 1..3 {
        new_test_ext().execute_with(|| {
            let mut signatures = vec![mock_sig_for(1), mock_sig_for(2), mock_sig_for(3)];
            signatures[rejected_at] = mock_sig_for(9);
            let scanned = deposit(signatures[..=rejected_at].to_vec())
                .get_dispatch_info()
                .weight;
            let result = deposit(signatures)
                .dispatch_bypass_filter(RuntimeOrigin::signed(1))
                .expect_err("non-member signer");
            assert_eq!(result.error, Error::<Test>::SignerNotCommitteeMember.into());
            assert_eq!(result.post_info.actual_weight, Some(scanned));
        });
    }
    for invalid_at in 0..3 {
        new_test_ext().execute_with(|| {
            let mut signatures = vec![mock_sig_for(1), mock_sig_for(2), mock_sig_for(3)];
            signatures[invalid_at].1 = [0xFF; 64];
            let declared = deposit(signatures.clone()).get_dispatch_info().weight;
            VERIFY_CALLS.with(|count| count.set(0));
            let result = deposit(signatures)
                .dispatch_bypass_filter(RuntimeOrigin::signed(1))
                .expect_err("bad signature");
            assert_eq!(result.error, Error::<Test>::InvalidSignature.into());
            assert_eq!(VERIFY_CALLS.with(|count| count.get()), invalid_at as u32 + 1);
            assert_eq!(result.post_info.actual_weight, Some(declared));
        });
    }
    new_test_ext().execute_with(|| {
        let call = crate::Call::<Test>::credit_deposit {
            target: ALICE,
            amount_ada: 1,
            cardano_tx_hash: [0x61; 32],
            signatures: mock_credit_sigs(),
        };
        let declared = call.get_dispatch_info().weight;
        let result = call
            .clone()
            .dispatch_bypass_filter(RuntimeOrigin::signed(1))
            .expect("valid deposit");
        assert_eq!(result.actual_weight, Some(declared));
        let replay = call
            .dispatch_bypass_filter(RuntimeOrigin::signed(1))
            .expect_err("replay");
        let no_signatures = crate::Call::<Test>::credit_deposit {
            target: ALICE,
            amount_ada: 1,
            cardano_tx_hash: [0x61; 32],
            signatures: vec![],
        }
        .get_dispatch_info()
        .weight;
        assert_eq!(replay.error, Error::<Test>::DepositAlreadyProcessed.into());
        assert_eq!(replay.post_info.actual_weight, Some(no_signatures));
    });
}

#[test]
fn genesis_safety_settled_batch_replay_checks_before_verification() {
    new_test_ext().execute_with(|| {
        let (cid, _, _) = vouchered_claim_with_voucher(0x71, 1_000);
        Claims::<Test>::mutate(cid, |c| c.as_mut().expect("claim").settled = true);
        VERIFY_CALLS.with(|count| count.set(0));
        assert_noop!(
            IntentSettlement::settle_batch_atomic(
                RuntimeOrigin::signed(1),
                vec![SettleBatchEntry {
                    claim_id: cid,
                    cardano_tx_hash: [0x74; 32],
                    settled_direct: false
                }]
                .try_into()
                .expect("one entry"),
                mock_settle_sigs()
            )
            .map_err(|e| e.error),
            Error::<Test>::BatchClaimAlreadySettled
        );
        assert_eq!(VERIFY_CALLS.with(|count| count.get()), 0);
    });
}

#[test]
fn genesis_safety_voucher_batch_replay_checks_before_verification() {
    new_test_ext().execute_with(|| {
        let (cid, iid, voucher) = vouchered_claim_with_voucher(0x72, 1_000);
        VERIFY_CALLS.with(|count| count.set(0));
        assert_noop!(
            IntentSettlement::request_batch_vouchers(
                RuntimeOrigin::signed(1),
                vec![RequestVoucherEntry {
                    claim_id: cid,
                    intent_id: iid,
                    voucher,
                    fairness_proof: good_fairness_proof(iid, 1_000)
                }]
                .try_into()
                .expect("one entry"),
                mock_voucher_sigs()
            )
            .map_err(|e| e.error),
            Error::<Test>::DuplicateVoucher
        );
        assert_eq!(VERIFY_CALLS.with(|count| count.get()), 0);
    });
}

#[test]
fn genesis_safety_terminal_intent_batch_checks_before_verification() {
    new_test_ext().execute_with(|| {
        let (_, iid, _) = vouchered_claim_with_voucher(0x73, 1_000);
        VERIFY_CALLS.with(|count| count.set(0));
        assert_noop!(
            IntentSettlement::attest_batch_intents(
                RuntimeOrigin::signed(1),
                vec![iid].try_into().expect("one entry"),
                mock_settle_sigs()
            )
            .map_err(|e| e.error),
            Error::<Test>::IntentStatusMismatch
        );
        assert_eq!(VERIFY_CALLS.with(|count| count.get()), 0);
    });
}

#[test]
fn genesis_safety_expired_policy_request_can_be_replaced_after_cutover() {
    genesis_ext().execute_with(|| {
        System::set_block_number(1);
        let (_, iid, _) = vouchered_claim_with_voucher(0x81, 1_000);
        let intent = Intents::<Test>::get(iid).expect("intent");
        let mut evidence = ExpiryEvidence {
            cardano_tx_hash: [0x81; 32],
            observed_at_depth: 15,
            observed_slot: 123,
            mainchain_genesis_hash: TestMainchainGenesisHash::get(),
            policy_id_witness: IntentSettlement::resolve_intent_policy_id(&intent).expect("policy"),
        };
        assert_ok!(IntentSettlement::request_expire_policy(
            RuntimeOrigin::signed(BOB),
            iid,
            evidence.cardano_tx_hash,
            evidence
        ));
        System::set_block_number(1 + TestSettlementRequestTtl::get() as u64);
        evidence.cardano_tx_hash = [0x82; 32];
        assert_noop!(
            IntentSettlement::request_expire_policy(
                RuntimeOrigin::signed(ALICE),
                iid,
                evidence.cardano_tx_hash,
                evidence
            ),
            Error::<Test>::ExpiryRequestAlreadyExists
        );
        System::set_block_number(System::block_number() + 1);
        assert_ok!(IntentSettlement::request_expire_policy(
            RuntimeOrigin::signed(ALICE),
            iid,
            evidence.cardano_tx_hash,
            evidence
        ));
        assert_ok!(IntentSettlement::attest_expire_policy(
            RuntimeOrigin::signed(1),
            iid,
            mock_settle_sigs()
        ));
        assert_eq!(
            Intents::<Test>::get(iid).expect("expired intent").status,
            IntentStatus::Expired
        );
        assert!(!PreAuditExpiry::<Test>::get(iid));
    });
}

#[test]
fn genesis_safety_signature_weights_cover_measured_runtime_samples() {
    use frame_support::weights::constants::RocksDbWeight;
    let samples: serde_json::Value =
        serde_json::from_str(include_str!("../benchmarking/signature-samples.json"))
            .expect("recorded FRAME benchmark JSON");
    let benchmark = &samples[0];
    let mut largest_bundle = 0;
    for sample in benchmark["time_results"].as_array().expect("time samples") {
        let count = sample["components"][0][1]
            .as_u64()
            .expect("signature count") as u32;
        largest_bundle = largest_bundle.max(count);
        let elapsed = sample["extrinsic_time"].as_u64().expect("nanoseconds") * 1_000;
        let weight = crate::signature_weights::threshold_signatures(count);
        assert!(
            weight.ref_time() >= elapsed + RocksDbWeight::get().reads(2).ref_time(),
            "{count} signatures: measured execution exceeds declared weight"
        );
        assert!(weight.proof_size() >= sample["proof_size"].as_u64().expect("recorded proof"));
    }
    assert_eq!(
        largest_bundle, 96,
        "benchmark reaches Materios MaxCommittee"
    );
    // Two independent StorageValues, each with three conservative trie layers.
    let proof_bound = (4 + 3 * 495) + (2 + 96 * 32 + 3 * 495);
    assert!(crate::signature_weights::threshold_signatures(1).proof_size() >= proof_bound);
}

#[test]
fn genesis_safety_honest_keeper_settles_after_junk_bond_slashed() {
    for batch in [false, true] {
        new_test_ext().execute_with(|| {
            let (cid, _, voucher) = vouchered_claim_with_voucher(0x81, 1_000);
            let mut evidence = settled_evidence_for(&voucher, 15, 123);
            evidence.cardano_tx_hash = [0xEE; 32];
            assert_ok!(IntentSettlement::request_settle(
                RuntimeOrigin::signed(BOB),
                cid,
                evidence.cardano_tx_hash,
                false,
                evidence,
                1
            ));

            fund_account(1, 1);
            fund_account(
                TestSettlementTreasuryPalletId::get().into_account_truncating(),
                1,
            );
            assert_ok!(IntentSettlement::slash_bad_settlement_evidence(
                RuntimeOrigin::signed(1),
                cid,
                FraudProof::TxNotFound,
                mock_settle_sigs()
            ));
            assert_eq!(Balances::reserved_balance(BOB), 0);
            assert_noop!(
                IntentSettlement::request_settle(
                    RuntimeOrigin::signed(BOB),
                    cid,
                    evidence.cardano_tx_hash,
                    false,
                    evidence,
                    1
                ),
                Error::<Test>::BondSlashedNoRelease
            );
            // A claim-wide tombstone left by an earlier runtime is inert.
            BondSlashedRequests::<Test>::insert(cid, ());
            evidence.cardano_tx_hash = [0x82; 32];
            if batch {
                assert_ok!(IntentSettlement::request_batch_settle(
                    RuntimeOrigin::signed(ALICE),
                    vec![SettleAttestedBatchEntry {
                        claim_id: cid,
                        settled_direct: false,
                        evidence
                    }]
                    .try_into()
                    .expect("one entry"),
                    1
                ));
            } else {
                assert_ok!(IntentSettlement::request_settle(
                    RuntimeOrigin::signed(ALICE),
                    cid,
                    evidence.cardano_tx_hash,
                    false,
                    evidence,
                    1
                ));
            }
            assert_ok!(IntentSettlement::attest_settle(
                RuntimeOrigin::signed(1),
                cid,
                mock_settle_sigs()
            ));
            assert!(Claims::<Test>::get(cid).expect("claim").settled);
        });
    }
}

#[test]
fn genesis_safety_single_attestation_duplicate_skips_verification() {
    new_test_ext().execute_with(|| {
        let (_, iid, _) = vouchered_claim_with_voucher(0x83, 1_000);
        Intents::<Test>::mutate(iid, |i| {
            i.as_mut().expect("intent").status = IntentStatus::Pending
        });
        let (pubkey, sig) = mock_sig_for(1);
        assert_ok!(IntentSettlement::attest_intent(
            RuntimeOrigin::signed(1),
            iid,
            pubkey,
            sig
        ));
        VERIFY_CALLS.with(|count| count.set(0));
        assert_noop!(
            IntentSettlement::attest_intent(RuntimeOrigin::signed(1), iid, pubkey, sig),
            Error::<Test>::DuplicatePubkey
        );
        assert_eq!(VERIFY_CALLS.with(|count| count.get()), 0);
    });
}

#[test]
fn genesis_safety_single_attestation_charges_signature() {
    use frame_support::dispatch::GetDispatchInfo;
    let (pubkey, sig) = mock_sig_for(1);
    let weight = crate::Call::<Test>::attest_intent {
        intent_id: H256::zero(),
        pubkey,
        sig,
    }
    .get_dispatch_info()
    .weight;
    assert!(weight.ref_time() >= crate::signature_weights::threshold_signatures(1).ref_time());
}

#[test]
fn genesis_safety_batch_intent_replay_skips_verification() {
    new_test_ext().execute_with(|| {
        let (_, iid, _) = vouchered_claim_with_voucher(0x84, 1_000);
        Intents::<Test>::mutate(iid, |i| {
            i.as_mut().expect("intent").status = IntentStatus::Attested
        });
        VERIFY_CALLS.with(|count| count.set(0));
        assert_ok!(IntentSettlement::attest_batch_intents(
            RuntimeOrigin::signed(1),
            vec![iid].try_into().expect("one intent"),
            mock_settle_sigs()
        ));
        assert_eq!(VERIFY_CALLS.with(|count| count.get()), 0);
    });
}

#[test]
fn genesis_safety_nonmember_slash_skips_verification() {
    new_test_ext().execute_with(|| {
        let (cid, _) = alice_request_and_bond(0x85, 1_000, 500);
        VERIFY_CALLS.with(|count| count.set(0));
        assert_noop!(
            IntentSettlement::slash_bad_settlement_evidence(
                RuntimeOrigin::signed(BOB),
                cid,
                FraudProof::TxNotFound,
                mock_settle_sigs()
            )
            .map_err(|error| error.error),
            Error::<Test>::NotCommitteeMember
        );
        assert_eq!(VERIFY_CALLS.with(|count| count.get()), 0);
    });
}

#[test]
fn genesis_safety_late_bond_rejected() {
    new_test_ext().execute_with(|| {
        let (cid, _, voucher) = vouchered_claim_with_voucher(0x86, 1_000);
        let evidence = settled_evidence_for(&voucher, 15, 123);
        ClaimSettlementRequests::<Test>::insert(
            cid,
            SettlementRequestRecord {
                requester: ALICE,
                evidence,
                settled_direct: false,
                submitted_block: 1,
                bond_amount: 0,
            },
        );
        fund_account(ALICE, 1_000);
        System::set_block_number(2 + TestSettlementRequestTtl::get() as u64);
        assert_noop!(
            IntentSettlement::post_settlement_bond(RuntimeOrigin::signed(ALICE), cid, 500),
            Error::<Test>::SettlementRequestExpired
        );
    });
}

#[test]
fn genesis_safety_reserve_deficit_does_not_block_replacement() {
    use frame_support::traits::ReservableCurrency;
    new_test_ext().execute_with(|| {
        let (cid, voucher) = alice_request_and_bond(0x87, 1_000, 500);
        let (imbalance, missing) = Balances::slash_reserved(&ALICE, 200);
        drop(imbalance);
        assert_eq!(missing, 0);
        let before = Balances::free_balance(ALICE);
        System::set_block_number(2 + TestSettlementRequestTtl::get() as u64);
        let evidence = settled_evidence_for(&voucher, 15, 123);
        assert_ok!(IntentSettlement::request_settle(
            RuntimeOrigin::signed(BOB),
            cid,
            evidence.cardano_tx_hash,
            false,
            evidence,
            1
        ));
        assert_eq!(Balances::free_balance(ALICE), before + 300);
        assert_eq!(Balances::reserved_balance(ALICE), 0);
        System::assert_has_event(RuntimeEvent::IntentSettlement(Event::SettlementBondReleased {
            claim_id: cid,
            requester: ALICE,
            amount: 300,
        }));
        System::assert_has_event(RuntimeEvent::IntentSettlement(
            Event::SettlementBondReserveDeficit {
                claim_id: cid,
                requester: ALICE,
                missing_amount: 200,
            },
        ));
    });
}

#[cfg(feature = "try-runtime")]
#[test]
fn genesis_safety_try_state_rejects_unknown_version_and_stale_progress() {
    use frame_support::traits::Hooks;
    genesis_ext().execute_with(|| {
        SettlementStorageVersion::<Test>::put(crate::SETTLEMENT_STORAGE_VERSION + 1);
        assert!(<IntentSettlement as Hooks<u64>>::try_state(0).is_err());
        assert!(<IntentSettlement as Hooks<u64>>::pre_upgrade().is_err());
        SettlementStorageVersion::<Test>::put(3);
        BondMigrationProgress::<Test>::put(
            BoundedVec::<ClaimId, frame_support::traits::ConstU32<MAX_SETTLE_BATCH>>::try_from(
                vec![H256::repeat_byte(1)],
            )
            .expect("bounded progress"),
        );
        assert!(<IntentSettlement as Hooks<u64>>::try_state(0).is_err());
    });
}

#[cfg(feature = "try-runtime")]
#[test]
fn genesis_safety_upgrade_checks_preserve_cutovers() {
    use frame_support::traits::Hooks;
    for (corrupt_stca, error) in [
        (true, "STCA cutover changed unexpectedly"),
        (false, "EXPP cutover changed unexpectedly"),
    ] {
        genesis_ext().execute_with(|| {
            System::set_block_number(100);
            SettlementStorageVersion::<Test>::put(1);
            StcaCutoverBlock::<Test>::put(25);
            PolicyExpireCutoverBlock::<Test>::put(0);
            let before = <IntentSettlement as Hooks<u64>>::pre_upgrade().expect("valid state");
            <IntentSettlement as Hooks<u64>>::on_runtime_upgrade();
            if corrupt_stca {
                StcaCutoverBlock::<Test>::put(50);
            } else {
                PolicyExpireCutoverBlock::<Test>::put(999);
            }
            assert_eq!(
                <IntentSettlement as Hooks<u64>>::post_upgrade(before),
                Err(error.into())
            );
        });
    }
}

#[test]
fn genesis_safety_unbonded_single_request_rejected() {
    new_test_ext().execute_with(|| {
        let (cid, _, voucher) = vouchered_claim_with_voucher(0x88, 1_000);
        let evidence = settled_evidence_for(&voucher, 15, 123);
        assert_noop!(
            IntentSettlement::request_settle(
                RuntimeOrigin::signed(ALICE),
                cid,
                evidence.cardano_tx_hash,
                false,
                evidence,
                0
            ),
            Error::<Test>::BondBelowMinimum
        );
    });
}

#[test]
fn genesis_safety_unbonded_batch_request_rejected() {
    new_test_ext().execute_with(|| {
        let (cid, _, voucher) = vouchered_claim_with_voucher(0x89, 1_000);
        let evidence = settled_evidence_for(&voucher, 15, 123);
        assert_noop!(
            IntentSettlement::request_batch_settle(
                RuntimeOrigin::signed(ALICE),
                vec![SettleAttestedBatchEntry {
                    claim_id: cid,
                    settled_direct: false,
                    evidence
                }]
                .try_into()
                .expect("one entry"),
                0
            ),
            Error::<Test>::BondBelowMinimum
        );
    });
}

#[test]
fn genesis_safety_request_enforces_configured_minimum() {
    new_test_ext().execute_with(|| {
        TestMinSettlementBond::set(100);
        let (cid, _, voucher) = vouchered_claim_with_voucher(0x90, 1_000);
        let evidence = settled_evidence_for(&voucher, 15, 123);
        assert_noop!(
            IntentSettlement::request_settle(
                RuntimeOrigin::signed(ALICE),
                cid,
                evidence.cardano_tx_hash,
                false,
                evidence,
                1
            ),
            Error::<Test>::BondBelowMinimum
        );
        TestMinSettlementBond::set(0);
    });
}

#[test]
fn genesis_safety_unfunded_replacement_rolls_back_old_refund() {
    new_test_ext().execute_with(|| {
        let (cid, voucher) = alice_request_and_bond(0x91, 1_000, 500);
        let _ = <Balances as frame_support::traits::Currency<u64>>::make_free_balance_be(&BOB, 0);
        System::set_block_number(2 + TestSettlementRequestTtl::get() as u64);
        let evidence = settled_evidence_for(&voucher, 15, 123);
        assert_noop!(
            IntentSettlement::request_settle(
                RuntimeOrigin::signed(BOB),
                cid,
                evidence.cardano_tx_hash,
                false,
                evidence,
                1
            ),
            pallet_balances::Error::<Test>::InsufficientBalance
        );
        assert_eq!(Balances::reserved_balance(ALICE), 500);
    });
}

#[test]
fn genesis_safety_batch_reserves_all_bonds_atomically() {
    new_test_ext().execute_with(|| {
        let (first, _, voucher1) = vouchered_claim_with_voucher(0x92, 1_000);
        let (second, _, voucher2) = vouchered_claim_with_voucher(0x93, 1_000);
        let _ = <Balances as frame_support::traits::Currency<u64>>::make_free_balance_be(&BOB, 150);
        let entries = vec![(first, voucher1), (second, voucher2)]
            .into_iter()
            .map(|(claim_id, voucher)| SettleAttestedBatchEntry {
                claim_id,
                settled_direct: false,
                evidence: settled_evidence_for(&voucher, 15, 123),
            })
            .collect::<Vec<_>>();
        assert_noop!(
            IntentSettlement::request_batch_settle(
                RuntimeOrigin::signed(BOB),
                entries.try_into().expect("two entries"),
                100
            ),
            pallet_balances::Error::<Test>::InsufficientBalance
        );
        assert!(!ClaimSettlementRequests::<Test>::contains_key(first));
    });
}

#[cfg(feature = "try-runtime")]
#[test]
fn genesis_safety_upgrade_checks_accept_legacy_migrations_and_genesis() {
    use frame_support::traits::{Hooks, ReservableCurrency};
    for version in 0..=crate::SETTLEMENT_STORAGE_VERSION {
        genesis_ext().execute_with(|| {
            System::set_block_number(100);
            SettlementStorageVersion::<Test>::put(version);
            if version > 0 && version < 3 {
                StcaCutoverBlock::<Test>::put(25);
            }
            if version == 2 {
                PolicyExpireCutoverBlock::<Test>::put(30);
            }
            let (cid, iid, voucher) = vouchered_claim_with_voucher(0x94, 1_000);
            if version == 3 {
                assert_ok!(Balances::reserve(&ALICE, 500));
                ClaimSettlementRequests::<Test>::insert(
                    cid,
                    SettlementRequestRecord {
                        requester: ALICE,
                        evidence: settled_evidence_for(&voucher, 15, 123),
                        settled_direct: false,
                        submitted_block: 100,
                        bond_amount: 500,
                    },
                );
            }
            Intents::<Test>::mutate(iid, |intent| {
                intent.as_mut().expect("intent").status = IntentStatus::Expired
            });
            let before = <IntentSettlement as Hooks<u64>>::pre_upgrade().expect("valid pre-state");
            <IntentSettlement as Hooks<u64>>::on_runtime_upgrade();
            assert_ok!(<IntentSettlement as Hooks<u64>>::post_upgrade(before));
            assert_ok!(<IntentSettlement as Hooks<u64>>::try_state(100));
            assert_eq!(SettlementStorageVersion::<Test>::get(), crate::SETTLEMENT_STORAGE_VERSION);
        });
    }
}

#[cfg(feature = "try-runtime")]
#[test]
fn genesis_safety_try_state_rejects_inconsistent_cutovers() {
    use frame_support::traits::Hooks;
    for (version, stca, expp) in [
        (0, 0, 10),
        (1, 0, 0),
        (2, 10, 0),
        (3, 10, 0),
        (3, 0, 10),
        (4, 10, 0),
        (4, 0, 10),
    ] {
        genesis_ext().execute_with(|| {
            SettlementStorageVersion::<Test>::put(version);
            StcaCutoverBlock::<Test>::put(stca);
            PolicyExpireCutoverBlock::<Test>::put(expp);
            assert!(<IntentSettlement as Hooks<u64>>::try_state(100).is_err());
        });
    }
}

#[cfg(feature = "try-runtime")]
#[test]
fn genesis_safety_upgrade_checks_reject_settlement_mutation_at_current_version() {
    use frame_support::traits::Hooks;
    genesis_ext().execute_with(|| {
        let before = <IntentSettlement as Hooks<u64>>::pre_upgrade().expect("valid pre-state");
        <IntentSettlement as Hooks<u64>>::on_runtime_upgrade();
        PreAuditSettlement::<Test>::insert(H256::repeat_byte(7), true);
        assert_eq!(
            <IntentSettlement as Hooks<u64>>::post_upgrade(before),
            Err("current-version settlement upgrade mutated settlement storage".into())
        );
    });
}

#[cfg(feature = "try-runtime")]
#[test]
fn genesis_safety_upgrade_checks_ignore_other_pallet_changes() {
    use frame_support::traits::Hooks;
    genesis_ext().execute_with(|| {
        let before = <IntentSettlement as Hooks<u64>>::pre_upgrade().expect("valid pre-state");
        <IntentSettlement as Hooks<u64>>::on_runtime_upgrade();
        sp_io::storage::set(b"other-pallet-upgrade", b"changed");
        assert_ok!(<IntentSettlement as Hooks<u64>>::post_upgrade(before));
    });
}

#[test]
fn genesis_safety_request_rejects_depth_above_maximum() {
    new_test_ext().execute_with(|| {
        let (cid, _, voucher) = vouchered_claim_with_voucher(0xA1, 1_000);
        let mut evidence = settled_evidence_for(&voucher, crate::MAX_OBSERVED_DEPTH + 1, 123);
        assert_noop!(
            IntentSettlement::request_settle(
                RuntimeOrigin::signed(BOB),
                cid,
                evidence.cardano_tx_hash,
                false,
                evidence,
                1
            ),
            Error::<Test>::FinalityDepthAboveMaximum
        );
        assert_noop!(
            IntentSettlement::request_batch_settle(
                RuntimeOrigin::signed(BOB),
                vec![SettleAttestedBatchEntry {
                    claim_id: cid,
                    settled_direct: false,
                    evidence
                }]
                .try_into()
                .expect("one entry"),
                1
            ),
            Error::<Test>::FinalityDepthAboveMaximum
        );
        evidence.observed_at_depth = crate::MAX_OBSERVED_DEPTH;
        assert_ok!(IntentSettlement::request_settle(
            RuntimeOrigin::signed(BOB),
            cid,
            evidence.cardano_tx_hash,
            false,
            evidence,
            1
        ));
    });
}

/// Files `junk` for the claim from BOB with a bond of 7. Depth `u32::MAX`
/// is written into storage after filing, as a request stored before the
/// depth cap would hold it.
fn file_junk_request(cid: ClaimId, junk: SettlementEvidence) {
    let mut filed = junk;
    filed.observed_at_depth = filed.observed_at_depth.min(crate::MAX_OBSERVED_DEPTH);
    assert_ok!(IntentSettlement::request_settle(
        RuntimeOrigin::signed(BOB),
        cid,
        filed.cardano_tx_hash,
        false,
        filed,
        7
    ));
    ClaimSettlementRequests::<Test>::mutate(cid, |request| {
        request.as_mut().expect("junk request").evidence = junk;
    });
}

#[test]
fn genesis_safety_committee_supersedes_unattestable_junk_and_settles() {
    for inflate_depth in [true, false] {
        new_test_ext().execute_with(|| {
            let (cid, iid, voucher) = vouchered_claim_with_voucher(0xA2, 1_000);
            let honest = settled_evidence_for(&voucher, 15, 123);
            let mut junk = honest;
            if inflate_depth {
                junk.observed_at_depth = u32::MAX;
            } else {
                junk.observed_slot = 999;
            }
            let bob_free = Balances::free_balance(BOB);
            file_junk_request(cid, junk);
            assert_eq!(Balances::reserved_balance(BOB), 7);

            assert_ok!(IntentSettlement::supersede_settlement_request(
                RuntimeOrigin::signed(1),
                cid,
                false,
                honest,
                mock_settle_sigs()
            )
            .map_err(|failure| failure.error));

            let claim = Claims::<Test>::get(cid).expect("claim");
            assert!(claim.settled);
            assert_eq!(claim.cardano_tx_hash, honest.cardano_tx_hash);
            assert_eq!(
                Intents::<Test>::get(iid).expect("intent").status,
                IntentStatus::Settled
            );
            assert!(!ClaimSettlementRequests::<Test>::contains_key(cid));
            assert!(!BondedClaimRequester::<Test>::contains_key(cid));
            assert_eq!(Balances::reserved_balance(BOB), 0);
            assert_eq!(Balances::free_balance(BOB), bob_free);
            System::assert_has_event(RuntimeEvent::IntentSettlement(
                Event::SettlementRequestSuperseded {
                    claim_id: cid,
                    requester: BOB,
                },
            ));
        });
    }
}

#[test]
fn genesis_safety_supersede_refuses_a_request_with_the_attested_evidence() {
    new_test_ext().execute_with(|| {
        let (cid, _, voucher) = vouchered_claim_with_voucher(0xA3, 1_000);
        let honest = settled_evidence_for(&voucher, 15, 123);
        file_junk_request(cid, honest);
        VERIFY_CALLS.with(|count| count.set(0));
        assert_noop!(
            IntentSettlement::supersede_settlement_request(
                RuntimeOrigin::signed(1),
                cid,
                false,
                honest,
                mock_settle_sigs()
            )
            .map_err(|failure| failure.error),
            Error::<Test>::SupersedeMatchesRequest
        );
        assert_eq!(VERIFY_CALLS.with(|count| count.get()), 0);
    });
}

#[test]
fn genesis_safety_supersede_requires_a_committee_threshold() {
    new_test_ext().execute_with(|| {
        let (cid, _, voucher) = vouchered_claim_with_voucher(0xA4, 1_000);
        let honest = settled_evidence_for(&voucher, 15, 123);
        let mut junk = honest;
        junk.observed_slot = 999;
        file_junk_request(cid, junk);
        let mut forged = mock_settle_sigs();
        forged[1].1 = [0xFF; 64];
        for (caller, signatures, error) in [
            (1, vec![mock_sig_for(1)], Error::<Test>::InsufficientSignatures),
            (1, forged, Error::<Test>::InvalidSignature),
            (BOB, mock_settle_sigs(), Error::<Test>::NotCommitteeMember),
        ] {
            assert_noop!(
                IntentSettlement::supersede_settlement_request(
                    RuntimeOrigin::signed(caller),
                    cid,
                    false,
                    honest,
                    signatures
                )
                .map_err(|failure| failure.error),
                error
            );
        }
        assert_eq!(
            ClaimSettlementRequests::<Test>::get(cid).expect("junk stays").evidence,
            junk
        );
        assert_eq!(Balances::reserved_balance(BOB), 7);
    });
}

#[test]
fn genesis_safety_supersede_checks_evidence_like_a_request() {
    new_test_ext().execute_with(|| {
        let (cid, _, voucher) = vouchered_claim_with_voucher(0xA5, 1_000);
        let (unrequested, _, other_voucher) = vouchered_claim_with_voucher(0xA6, 1_000);
        let honest = settled_evidence_for(&voucher, 15, 123);
        let mut junk = honest;
        junk.observed_slot = 999;
        file_junk_request(cid, junk);
        let mut wrong_amount = honest;
        wrong_amount.amount_lovelace += 1;
        let mut too_deep = honest;
        too_deep.observed_at_depth = crate::MAX_OBSERVED_DEPTH + 1;
        for (claim_id, evidence, error) in [
            (cid, wrong_amount, Error::<Test>::SettlementEvidenceMismatch),
            (cid, too_deep, Error::<Test>::FinalityDepthAboveMaximum),
            (
                unrequested,
                settled_evidence_for(&other_voucher, 15, 123),
                Error::<Test>::SettlementRequestMissing,
            ),
        ] {
            assert_noop!(
                IntentSettlement::supersede_settlement_request(
                    RuntimeOrigin::signed(1),
                    claim_id,
                    false,
                    evidence,
                    mock_settle_sigs()
                )
                .map_err(|failure| failure.error),
                error
            );
        }
    });
}

const OTHER_PALLET_RESERVE: [u8; 8] = *b"otherpal";

fn settlement_reserve(who: u64) -> u128 {
    use frame_support::traits::NamedReservableCurrency;
    Balances::reserved_balance_named(&crate::SETTLEMENT_BOND_RESERVE_ID, &who)
}

#[test]
fn genesis_safety_bonds_are_held_under_the_settlement_reserve_id() {
    new_test_ext().execute_with(|| {
        let (cid, _) = alice_request_and_bond(0xB1, 1_000, 500);
        assert_eq!(settlement_reserve(ALICE), 500);
        assert_ok!(IntentSettlement::attest_settle(
            RuntimeOrigin::signed(1),
            cid,
            mock_settle_sigs()
        )
        .map_err(|error| error.error));
        assert_eq!(settlement_reserve(ALICE), 500);
        System::set_block_number(System::block_number() + TestBondReleaseDelayBlocks::get() as u64);
        assert_ok!(IntentSettlement::release_settlement_bond(
            RuntimeOrigin::signed(BOB),
            cid
        ));
        assert_eq!(settlement_reserve(ALICE), 0);
        assert_eq!(Balances::reserved_balance(ALICE), 0);
    });
}

#[test]
fn genesis_safety_refund_never_draws_on_another_pallets_reserve() {
    use frame_support::traits::NamedReservableCurrency;
    new_test_ext().execute_with(|| {
        let (cid, voucher) = alice_request_and_bond(0xB2, 1_000, 500);
        assert_ok!(Balances::reserve_named(&OTHER_PALLET_RESERVE, &ALICE, 1_000));
        let (imbalance, unslashed) =
            Balances::slash_reserved_named(&crate::SETTLEMENT_BOND_RESERVE_ID, &ALICE, 200);
        drop(imbalance);
        assert_eq!(unslashed, 0);
        let free = Balances::free_balance(ALICE);
        System::set_block_number(2 + TestSettlementRequestTtl::get() as u64);
        let evidence = settled_evidence_for(&voucher, 15, 123);
        assert_ok!(IntentSettlement::request_settle(
            RuntimeOrigin::signed(BOB),
            cid,
            evidence.cardano_tx_hash,
            false,
            evidence,
            1
        ));
        assert_eq!(Balances::free_balance(ALICE), free + 300);
        assert_eq!(Balances::reserved_balance_named(&OTHER_PALLET_RESERVE, &ALICE), 1_000);
        assert_eq!(Balances::reserved_balance(ALICE), 1_000);
        System::assert_has_event(RuntimeEvent::IntentSettlement(
            Event::SettlementBondReserveDeficit {
                claim_id: cid,
                requester: ALICE,
                missing_amount: 200,
            },
        ));
    });
}

#[test]
fn genesis_safety_slash_never_draws_on_another_pallets_reserve() {
    use frame_support::traits::NamedReservableCurrency;
    new_test_ext().execute_with(|| {
        let (cid, _) = alice_request_and_bond(0xB3, 1_000, 500);
        assert_ok!(Balances::reserve_named(&OTHER_PALLET_RESERVE, &ALICE, 1_000));
        let (imbalance, _) =
            Balances::slash_reserved_named(&crate::SETTLEMENT_BOND_RESERVE_ID, &ALICE, 200);
        drop(imbalance);
        fund_account(1, 1);
        let treasury: u64 = TestSettlementTreasuryPalletId::get().into_account_truncating();
        fund_account(treasury, 1);
        let watcher_free = Balances::free_balance(1);
        let treasury_free = Balances::free_balance(treasury);
        assert_ok!(IntentSettlement::slash_bad_settlement_evidence(
            RuntimeOrigin::signed(1),
            cid,
            FraudProof::TxNotFound,
            mock_settle_sigs()
        )
        .map_err(|error| error.error));
        assert_eq!(Balances::free_balance(1), watcher_free + 250);
        assert_eq!(Balances::free_balance(treasury), treasury_free + 50);
        assert_eq!(Balances::reserved_balance_named(&OTHER_PALLET_RESERVE, &ALICE), 1_000);
        assert_eq!(Balances::reserved_balance(ALICE), 1_000);
        System::assert_has_event(RuntimeEvent::IntentSettlement(Event::SettlementBondSlashed {
            claim_id: cid,
            requester: ALICE,
            watcher: 1,
            watcher_share: 250,
            treasury_share: 50,
            fraud_proof: FraudProof::TxNotFound,
        }));
        System::assert_has_event(RuntimeEvent::IntentSettlement(
            Event::SettlementBondReserveDeficit {
                claim_id: cid,
                requester: ALICE,
                missing_amount: 200,
            },
        ));
    });
}

#[test]
fn genesis_safety_upgrade_moves_outstanding_bonds_to_the_settlement_reserve() {
    use frame_support::traits::{OnRuntimeUpgrade, ReservableCurrency};
    new_test_ext().execute_with(|| {
        let (pending, _, voucher) = vouchered_claim_with_voucher(0xB4, 1_000);
        let (attested, _, _) = vouchered_claim_with_voucher(0xB5, 1_000);
        SettlementStorageVersion::<Test>::put(3);
        StcaCutoverBlock::<Test>::put(25);
        PolicyExpireCutoverBlock::<Test>::put(25);
        fund_account(ALICE, 1_000);
        assert_ok!(Balances::reserve(&ALICE, 500));
        assert_ok!(Balances::reserve(&ALICE, 100));
        ClaimSettlementRequests::<Test>::insert(
            pending,
            SettlementRequestRecord {
                requester: ALICE,
                evidence: settled_evidence_for(&voucher, 15, 123),
                settled_direct: false,
                submitted_block: 1,
                bond_amount: 500,
            },
        );
        fund_account(BOB, 1_000);
        assert_ok!(Balances::reserve(&BOB, 400));
        BondedClaimAttestedAt::<Test>::insert(attested, 1);
        BondedClaimRequester::<Test>::insert(attested, (BOB, 400));

        <IntentSettlement as OnRuntimeUpgrade>::on_runtime_upgrade();

        assert_eq!(SettlementStorageVersion::<Test>::get(), crate::SETTLEMENT_STORAGE_VERSION);
        assert_eq!(settlement_reserve(ALICE), 500);
        assert_eq!(Balances::reserved_balance(ALICE), 600);
        assert_eq!(settlement_reserve(BOB), 400);
        assert_eq!(Balances::reserved_balance(BOB), 400);
        let root = sp_io::storage::root(sp_runtime::StateVersion::V1);
        <IntentSettlement as OnRuntimeUpgrade>::on_runtime_upgrade();
        assert_eq!(sp_io::storage::root(sp_runtime::StateVersion::V1), root);

        System::set_block_number(1 + TestBondReleaseDelayBlocks::get() as u64);
        assert_ok!(IntentSettlement::release_settlement_bond(
            RuntimeOrigin::signed(ALICE),
            attested
        ));
        assert_eq!(Balances::reserved_balance(BOB), 0);
        System::set_block_number(2 + TestSettlementRequestTtl::get() as u64);
        assert_ok!(IntentSettlement::release_settlement_bond(
            RuntimeOrigin::signed(BOB),
            pending
        ));
        assert_eq!(Balances::reserved_balance(ALICE), 100);
    });
}

#[cfg(feature = "try-runtime")]
#[test]
fn genesis_safety_try_state_rejects_an_unbacked_settlement_bond() {
    use frame_support::traits::{Hooks, NamedReservableCurrency};
    new_test_ext().execute_with(|| {
        let (_, _) = alice_request_and_bond(0xB6, 1_000, 500);
        SettlementStorageVersion::<Test>::put(crate::SETTLEMENT_STORAGE_VERSION);
        assert_ok!(<IntentSettlement as Hooks<u64>>::try_state(1));
        Balances::unreserve_named(&crate::SETTLEMENT_BOND_RESERVE_ID, &ALICE, 1);
        assert_eq!(
            <IntentSettlement as Hooks<u64>>::try_state(1),
            Err("settlement bonds exceed the settlement reserve".into())
        );
    });
}
