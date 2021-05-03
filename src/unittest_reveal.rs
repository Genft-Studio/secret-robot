use crate::unittest_helpers::{init_helper_with_config, extract_error_msg, set_contract_status};
use crate::msg::{HandleMsg, ContractStatus};
use crate::contract::handle;
use cosmwasm_std::testing::mock_env;
use cosmwasm_std::HumanAddr;
use crate::token::Metadata;
use std::collections::HashSet;
use crate::state::{load, TOKENS_KEY, PREFIX_MAP_TO_INDEX, PREFIX_MAP_TO_ID, PREFIX_PRIV_META, PREFIX_PUB_META, may_load};
use cosmwasm_storage::ReadonlyPrefixedStorage;

// test Reveal
#[test]
fn test_reveal() {
    let (init_result, mut deps) =
        init_helper_with_config(true, false, true, false, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // test token does not exist when supply is public
    let handle_msg = HandleMsg::Reveal {
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("Token ID: MyNFT not found"));

    let (init_result, mut deps) =
        init_helper_with_config(false, false, true, false, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // test token does not exist when supply is private
    let handle_msg = HandleMsg::Reveal {
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("You do not own token MyNFT"));

    let (init_result, mut deps) =
        init_helper_with_config(false, false, false, false, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::MintNft {
        token_id: Some("MyNFT".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: Some(Metadata {
            name: Some("MySealedNFT".to_string()),
            description: Some("Sealed metadata test".to_string()),
            image: Some("sealed_uri".to_string()),
        }),
        public_metadata: None,
        memo: Some("Mint it baby!".to_string()),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    set_contract_status(&mut deps, ContractStatus::StopAll);

    let handle_msg = HandleMsg::Reveal {
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("The contract admin has temporarily disabled this action"));

    set_contract_status(&mut deps, ContractStatus::StopTransactions);

    // test sealed metadata not enabled
    let handle_msg = HandleMsg::Reveal {
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("Sealed metadata functionality is not enabled for this contract"));

    // test someone other than owner tries to unwrap
    let (init_result, mut deps) =
        init_helper_with_config(false, false, true, false, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    let handle_msg = HandleMsg::MintNft {
        token_id: Some("MyNFT".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: Some(Metadata {
            name: Some("MySealedNFT".to_string()),
            description: Some("Sealed metadata test".to_string()),
            image: Some("sealed_uri".to_string()),
        }),
        public_metadata: None,
        memo: Some("Mint it baby!".to_string()),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::Reveal {
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("You do not own token MyNFT"));

    // sanity check, unwrap to public metadata
    let handle_msg = HandleMsg::Reveal {
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let tokens: HashSet<String> = load(&deps.storage, TOKENS_KEY).unwrap();
    assert!(tokens.contains("MyNFT"));
    let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
    let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
    let token_key = index.to_le_bytes();
    let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
    let id: String = load(&map2id, &token_key).unwrap();
    assert_eq!("MyNFT".to_string(), id);
    let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
    let priv_meta: Option<Metadata> = may_load(&priv_store, &token_key).unwrap();
    assert!(priv_meta.is_none());
    let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
    let pub_meta: Metadata = load(&pub_store, &token_key).unwrap();
    assert_eq!(pub_meta.name, Some("MySealedNFT".to_string()));
    assert_eq!(
        pub_meta.description,
        Some("Sealed metadata test".to_string())
    );
    assert_eq!(pub_meta.image, Some("sealed_uri".to_string()));

    // test trying to unwrap token that has already been unwrapped
    let handle_msg = HandleMsg::Reveal {
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("This token has already been unwrapped"));

    // sanity check, unwrap but keep private
    let (init_result, mut deps) =
        init_helper_with_config(false, false, true, true, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("MyNFT".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: Some(Metadata {
            name: Some("MySealedNFT".to_string()),
            description: Some("Sealed metadata test".to_string()),
            image: Some("sealed_uri".to_string()),
        }),
        public_metadata: None,
        memo: Some("Mint it baby!".to_string()),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::Reveal {
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
    let priv_meta: Metadata = load(&priv_store, &token_key).unwrap();
    assert_eq!(priv_meta.name, Some("MySealedNFT".to_string()));
    assert_eq!(
        priv_meta.description,
        Some("Sealed metadata test".to_string())
    );
    assert_eq!(priv_meta.image, Some("sealed_uri".to_string()));
    let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
    let pub_meta: Option<Metadata> = may_load(&pub_store, &token_key).unwrap();
    assert!(pub_meta.is_none());
}
