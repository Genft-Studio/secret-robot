use crate::unittest_helpers::{init_helper_default, set_contract_status, extract_error_msg};
use crate::msg::{ContractStatus, HandleMsg};
use cosmwasm_std::{HumanAddr, CanonicalAddr, Api};
use crate::contract::handle;
use cosmwasm_std::testing::mock_env;
use crate::state::{load, MINTERS_KEY, may_load, Config, CONFIG_KEY};

// test add minters
#[test]
fn test_add_minters() {
    let (init_result, mut deps) = init_helper_default();
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // test adding minters when status prevents it
    set_contract_status(&mut deps, ContractStatus::StopAll);

    let minters = vec![
        HumanAddr("alice".to_string()),
        HumanAddr("bob".to_string()),
        HumanAddr("bob".to_string()),
        HumanAddr("alice".to_string()),
    ];
    let handle_msg = HandleMsg::AddMinters {
        minters: minters.clone(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("The contract admin has temporarily disabled this action"));

    // you can still add minters when transactions are stopped
    set_contract_status(&mut deps, ContractStatus::StopTransactions);

    // test non admin trying to add minters
    let handle_msg = HandleMsg::AddMinters {
        minters: minters.clone(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(
        error.contains("This is an admin command and can only be run from the admin address")
    );

    // sanity check
    let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
    let alice_raw = deps
        .api
        .canonical_address(&HumanAddr("alice".to_string()))
        .unwrap();
    let bob_raw = deps
        .api
        .canonical_address(&HumanAddr("bob".to_string()))
        .unwrap();
    let admin_raw = deps
        .api
        .canonical_address(&HumanAddr("admin".to_string()))
        .unwrap();
    // verify the minters we will add are not already in the list
    assert!(!cur_minter.contains(&alice_raw));
    assert!(!cur_minter.contains(&bob_raw));
    let handle_msg = HandleMsg::AddMinters {
        minters,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(result.is_ok());

    // verify the new minters were added
    let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
    assert_eq!(cur_minter.len(), 3);
    assert!(cur_minter.contains(&alice_raw));
    assert!(cur_minter.contains(&bob_raw));
    assert!(cur_minter.contains(&admin_raw));

    // let's try an empty list to see if it breaks
    let minters = vec![];
    let handle_msg = HandleMsg::AddMinters {
        minters,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(result.is_ok());

    // verify it's the same list
    let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
    assert_eq!(cur_minter.len(), 3);
    assert!(cur_minter.contains(&alice_raw));
    assert!(cur_minter.contains(&bob_raw));
    assert!(cur_minter.contains(&admin_raw));
}

// test remove minters
#[test]
fn test_remove_minters() {
    let (init_result, mut deps) = init_helper_default();
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // test removing minters when status prevents it
    set_contract_status(&mut deps, ContractStatus::StopAll);

    let minters = vec![
        HumanAddr("alice".to_string()),
        HumanAddr("bob".to_string()),
        HumanAddr("charlie".to_string()),
        HumanAddr("bob".to_string()),
    ];
    let handle_msg = HandleMsg::RemoveMinters {
        minters: minters.clone(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("The contract admin has temporarily disabled this action"));

    // you can still remove minters when transactions are stopped
    set_contract_status(&mut deps, ContractStatus::StopTransactions);

    // test non admin trying to remove minters
    let handle_msg = HandleMsg::RemoveMinters {
        minters: minters.clone(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(
        error.contains("This is an admin command and can only be run from the admin address")
    );

    // sanity check
    let alice_raw = deps
        .api
        .canonical_address(&HumanAddr("alice".to_string()))
        .unwrap();
    let bob_raw = deps
        .api
        .canonical_address(&HumanAddr("bob".to_string()))
        .unwrap();
    let charlie_raw = deps
        .api
        .canonical_address(&HumanAddr("charlie".to_string()))
        .unwrap();
    let admin_raw = deps
        .api
        .canonical_address(&HumanAddr("admin".to_string()))
        .unwrap();
    let handle_msg = HandleMsg::AddMinters {
        minters: minters.clone(),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(result.is_ok());

    // verify the new minters were added
    let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
    assert_eq!(cur_minter.len(), 4);
    assert!(cur_minter.contains(&alice_raw));
    assert!(cur_minter.contains(&bob_raw));
    assert!(cur_minter.contains(&charlie_raw));
    assert!(cur_minter.contains(&admin_raw));

    // let's give it an empty list to see if it breaks
    let minters = vec![];
    let handle_msg = HandleMsg::RemoveMinters {
        minters,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(result.is_ok());

    // verify it is the same list
    let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
    assert_eq!(cur_minter.len(), 4);
    assert!(cur_minter.contains(&alice_raw));
    assert!(cur_minter.contains(&bob_raw));
    assert!(cur_minter.contains(&charlie_raw));
    assert!(cur_minter.contains(&admin_raw));

    // let's throw some repeats to see if it breaks
    let minters = vec![
        HumanAddr("alice".to_string()),
        HumanAddr("bob".to_string()),
        HumanAddr("alice".to_string()),
        HumanAddr("charlie".to_string()),
    ];
    let handle_msg = HandleMsg::RemoveMinters {
        minters,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(result.is_ok());

    // verify the minters were removed
    let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
    assert_eq!(cur_minter.len(), 1);
    assert!(!cur_minter.contains(&alice_raw));
    assert!(!cur_minter.contains(&bob_raw));
    assert!(!cur_minter.contains(&charlie_raw));
    assert!(cur_minter.contains(&admin_raw));

    // let's remove the last one
    let handle_msg = HandleMsg::RemoveMinters {
        minters: vec![HumanAddr("admin".to_string())],
        padding: None,
    };
    let result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(result.is_ok());

    // verify the minters were removed
    let cur_minter: Option<Vec<CanonicalAddr>> = may_load(&deps.storage, MINTERS_KEY).unwrap();
    assert!(cur_minter.is_none());
}

// test set minters
#[test]
fn test_set_minters() {
    let (init_result, mut deps) = init_helper_default();
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // test setting minters when status prevents it
    set_contract_status(&mut deps, ContractStatus::StopAll);

    let minters = vec![
        HumanAddr("alice".to_string()),
        HumanAddr("bob".to_string()),
        HumanAddr("charlie".to_string()),
        HumanAddr("bob".to_string()),
        HumanAddr("alice".to_string()),
    ];
    let handle_msg = HandleMsg::SetMinters {
        minters: minters.clone(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("The contract admin has temporarily disabled this action"));

    // you can still set minters when transactions are stopped
    set_contract_status(&mut deps, ContractStatus::StopTransactions);

    // test non admin trying to set minters
    let handle_msg = HandleMsg::SetMinters {
        minters: minters.clone(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(
        error.contains("This is an admin command and can only be run from the admin address")
    );

    // sanity check
    let alice_raw = deps
        .api
        .canonical_address(&HumanAddr("alice".to_string()))
        .unwrap();
    let bob_raw = deps
        .api
        .canonical_address(&HumanAddr("bob".to_string()))
        .unwrap();
    let charlie_raw = deps
        .api
        .canonical_address(&HumanAddr("charlie".to_string()))
        .unwrap();
    let handle_msg = HandleMsg::SetMinters {
        minters: minters.clone(),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(result.is_ok());

    // verify the new minters were added
    let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
    assert_eq!(cur_minter.len(), 3);
    assert!(cur_minter.contains(&alice_raw));
    assert!(cur_minter.contains(&bob_raw));
    assert!(cur_minter.contains(&charlie_raw));
    // let's try an empty list
    let minters = vec![];
    let handle_msg = HandleMsg::SetMinters {
        minters,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    assert!(result.is_ok());

    // verify the minters were removed
    let cur_minter: Option<Vec<CanonicalAddr>> = may_load(&deps.storage, MINTERS_KEY).unwrap();
    assert!(cur_minter.is_none());
}

// test change admin
#[test]
fn test_change_admin() {
    let (init_result, mut deps) = init_helper_default();
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // test changing admin when status prevents it
    set_contract_status(&mut deps, ContractStatus::StopAll);

    let handle_msg = HandleMsg::ChangeAdmin {
        address: HumanAddr("alice".to_string()),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("The contract admin has temporarily disabled this action"));

    // you can still change admin when transactions are stopped
    set_contract_status(&mut deps, ContractStatus::StopTransactions);

    // test non admin trying to change admin
    let handle_msg = HandleMsg::ChangeAdmin {
        address: HumanAddr("alice".to_string()),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(
        error.contains("This is an admin command and can only be run from the admin address")
    );

    // sanity check
    let alice_raw = deps
        .api
        .canonical_address(&HumanAddr("alice".to_string()))
        .unwrap();
    let admin_raw = deps
        .api
        .canonical_address(&HumanAddr("admin".to_string()))
        .unwrap();
    // verify admin is the current admin
    let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
    assert_eq!(config.admin, admin_raw);
    // change it to alice
    let handle_msg = HandleMsg::ChangeAdmin {
        address: HumanAddr("alice".to_string()),
        padding: None,
    };
    let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    // verify admin was changed
    let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
    assert_eq!(config.admin, alice_raw);
}

// test set contract status
#[test]
fn test_set_contract_status() {
    let (init_result, mut deps) = init_helper_default();
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // test non admin trying to change status
    let handle_msg = HandleMsg::SetContractStatus {
        level: ContractStatus::StopAll,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(
        error.contains("This is an admin command and can only be run from the admin address")
    );

    // sanity check
    // verify current status is normal
    let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
    assert_eq!(config.status, ContractStatus::Normal.to_u8());

    // change it to StopAll
    let handle_msg = HandleMsg::SetContractStatus {
        level: ContractStatus::StopAll,
        padding: None,
    };
    let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

    // verify status was changed
    let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
    assert_eq!(config.status, ContractStatus::StopAll.to_u8());
}

