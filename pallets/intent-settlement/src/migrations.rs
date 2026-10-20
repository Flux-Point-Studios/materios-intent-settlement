//! Storage migrations a runtime registers in its `Executive`, which runs them
//! before the pallets' own `on_runtime_upgrade` hooks.

use crate::{
    pallet::{CardanoIds, Config, SettlementStorageVersion},
    types::CardanoIdentity,
    NAMED_RESERVE_VERSION, SETTLEMENT_STORAGE_VERSION,
};
use core::marker::PhantomData;
use frame_support::{
    traits::{Get, OnRuntimeUpgrade},
    weights::Weight,
};
#[cfg(feature = "try-runtime")]
use {
    alloc::vec::Vec,
    frame_support::ensure,
    parity_scale_codec::{Decode, Encode},
    sp_runtime::TryRuntimeError,
};

/// Version 4 to 5 on a chain that ran before genesis stored its Cardano
/// network: stores `T::CardanoIdsToSeed`, the network its settlement has been
/// binding, in `CardanoIds`. That gives none for a chain whose network the
/// runtime does not know, and that chain keeps version 4 with no ids, so
/// settlement refuses rather than bind another network. Every other version
/// is left alone.
///
/// Costs a read of the version and one for `T::CardanoIdsToSeed`, which looks
/// up which chain this is, and two writes when it seeds.
pub struct SeedCardanoIds<T>(PhantomData<T>);

/// The ids [`SeedCardanoIds`] stores on this chain: `T::CardanoIdsToSeed`'s on
/// a version-4 chain, none on any other.
pub(crate) fn ids_to_seed<T: Config>() -> Option<CardanoIdentity> {
    (SettlementStorageVersion::<T>::get() == NAMED_RESERVE_VERSION)
        .then(T::CardanoIdsToSeed::get)
        .flatten()
}

impl<T: Config> OnRuntimeUpgrade for SeedCardanoIds<T> {
    fn on_runtime_upgrade() -> Weight {
        let db = T::DbWeight::get();
        if SettlementStorageVersion::<T>::get() != NAMED_RESERVE_VERSION {
            return db.reads(1);
        }
        let Some(ids) = T::CardanoIdsToSeed::get() else {
            log::error!(
                target: "runtime::intent-settlement",
                "no Cardano ids for this chain: settlement stays at storage version {NAMED_RESERVE_VERSION} and refuses every voucher and settlement",
            );
            return db.reads(2);
        };
        CardanoIds::<T>::put(ids);
        SettlementStorageVersion::<T>::put(SETTLEMENT_STORAGE_VERSION);
        log::info!(
            target: "runtime::intent-settlement",
            "stored the Cardano ids settlement binds: {ids:?}",
        );
        db.reads_writes(2, 2)
    }

    #[cfg(feature = "try-runtime")]
    fn pre_upgrade() -> Result<Vec<u8>, TryRuntimeError> {
        let version = SettlementStorageVersion::<T>::get();
        let seeded = ids_to_seed::<T>();
        ensure!(
            version != NAMED_RESERVE_VERSION || !CardanoIds::<T>::exists(),
            "a version-4 chain already stores Cardano ids"
        );
        Ok((version, CardanoIds::<T>::get(), seeded).encode())
    }

    #[cfg(feature = "try-runtime")]
    fn post_upgrade(state: Vec<u8>) -> Result<(), TryRuntimeError> {
        let (version, stored, seeded) =
            <(u32, Option<CardanoIdentity>, Option<CardanoIdentity>)>::decode(&mut &state[..])
                .map_err(|_| "SeedCardanoIds pre_upgrade state does not decode")?;
        let expected = match seeded {
            Some(ids) => (SETTLEMENT_STORAGE_VERSION, Some(ids)),
            None => (version, stored),
        };
        ensure!(
            (SettlementStorageVersion::<T>::get(), CardanoIds::<T>::get()) == expected,
            "SeedCardanoIds stored other ids or another version than it seeds"
        );
        Ok(())
    }
}
