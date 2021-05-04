//#![allow(clippy::field_reassign_with_default)]
pub mod contract;
pub mod expiration;
pub mod msg;
mod rand;
pub mod receiver;
pub mod state;
pub mod token;
mod unittest_batch_burn;
mod unittest_batch_mint;
mod unittest_handles;
mod unittest_burn;
mod unittest_cw721_approve;
mod unittest_cw721_revoke;
mod unittest_helpers;
mod unittest_mint;
mod unittest_private_metadata;
mod unittest_public_metadata;
mod unittest_queries;
mod unittest_reveal;
mod unittest_transfer;
mod unittest_whitelisted_approval;
mod utils;
mod viewing_key;

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::contract;
    use cosmwasm_std::{
        do_handle, do_init, do_query, ExternalApi, ExternalQuerier, ExternalStorage,
    };

    #[no_mangle]
    extern "C" fn init(env_ptr: u32, msg_ptr: u32) -> u32 {
        do_init(
            &contract::init::<ExternalStorage, ExternalApi, ExternalQuerier>,
            env_ptr,
            msg_ptr,
        )
    }

    #[no_mangle]
    extern "C" fn handle(env_ptr: u32, msg_ptr: u32) -> u32 {
        do_handle(
            &contract::handle::<ExternalStorage, ExternalApi, ExternalQuerier>,
            env_ptr,
            msg_ptr,
        )
    }

    #[no_mangle]
    extern "C" fn query(msg_ptr: u32) -> u32 {
        do_query(
            &contract::query::<ExternalStorage, ExternalApi, ExternalQuerier>,
            msg_ptr,
        )
    }

    // Other C externs like cosmwasm_vm_version_1, allocate, deallocate are available
    // automatically because we `use cosmwasm_std`.
}
