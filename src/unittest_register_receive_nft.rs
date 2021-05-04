use crate::unittest_helpers::{init_helper_default, set_contract_status, extract_error_msg};
use crate::msg::{ContractStatus, HandleMsg};
use crate::contract::handle;
use cosmwasm_std::testing::mock_env;
use cosmwasm_storage::ReadonlyPrefixedStorage;
use crate::state::{PREFIX_RECEIVERS, load};
use cosmwasm_std::{Api, HumanAddr};

// test register receive_nft
#[test]
fn test_register_receive_nft() {
    let (init_result, mut deps) = init_helper_default();
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // test register when status prevents it
    set_contract_status(&mut deps, ContractStatus::StopAll);

    let handle_msg = HandleMsg::RegisterReceiveNft {
        code_hash: "alice code hash".to_string(),
        also_implements_batch_receive_nft: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("The contract admin has temporarily disabled this action"));

    // you can still register when transactions are stopped
    set_contract_status(&mut deps, ContractStatus::StopTransactions);

    // sanity check
    let handle_msg = HandleMsg::RegisterReceiveNft {
        code_hash: "alice code hash".to_string(),
        also_implements_batch_receive_nft: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let store = ReadonlyPrefixedStorage::new(PREFIX_RECEIVERS, &deps.storage);
    let hash: String = load(
        &store,
        deps.api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap()
            .as_slice(),
    )
        .unwrap();
    assert_eq!(&hash, "alice code hash");
}
