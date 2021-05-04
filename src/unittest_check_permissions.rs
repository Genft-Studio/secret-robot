use crate::unittest_helpers::{init_helper_with_config, extract_error_msg, init_helper_default};
use cosmwasm_std::{BlockInfo, Api, HumanAddr};
use crate::msg::{HandleMsg, AccessLevel};
use crate::token::{Metadata, Token};
use crate::contract::{handle, check_permission};
use cosmwasm_std::testing::mock_env;
use cosmwasm_storage::ReadonlyPrefixedStorage;
use crate::state::{PREFIX_INFOS, json_load, PermissionType};
use crate::expiration::Expiration;

// test permissioning works
#[test]
fn test_check_permission() {
    let (init_result, mut deps) =
        init_helper_with_config(true, false, false, false, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );
    let block = BlockInfo {
        height: 1,
        time: 1,
        chain_id: "secret-2".to_string(),
    };
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
    let nft1_key = 0u32.to_le_bytes();
    let nft2_key = 1u32.to_le_bytes();
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT1".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        public_metadata: Some(Metadata {
            name: Some("My1".to_string()),
            description: Some("Pub 1".to_string()),
            image: Some("URI 1".to_string()),
        }),
        private_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT2".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        public_metadata: Some(Metadata {
            name: Some("My2".to_string()),
            description: Some("Pub 2".to_string()),
            image: Some("URI 2".to_string()),
        }),
        private_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    // test not approved
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token1: Token = json_load(&info_store, &nft1_key).unwrap();
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::ViewOwner,
        &mut Vec::new(),
        "not approved",
        false,
    );
    let error = extract_error_msg(check_perm);
    assert!(error.contains("not approved"));

    // test owner is public for the contract
    let (init_result, mut deps) =
        init_helper_with_config(true, true, false, false, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT1".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        public_metadata: Some(Metadata {
            name: Some("My1".to_string()),
            description: Some("Pub 1".to_string()),
            image: Some("URI 1".to_string()),
        }),
        private_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT2".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        public_metadata: Some(Metadata {
            name: Some("My2".to_string()),
            description: Some("Pub 2".to_string()),
            image: Some("URI 2".to_string()),
        }),
        private_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::ViewOwner,
        &mut Vec::new(),
        "not approved",
        true,
    );
    assert!(check_perm.is_ok());

    // test owner makes their tokens private when the contract has public ownership
    let handle_msg = HandleMsg::MakeOwnershipPrivate { padding: None };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::ViewOwner,
        &mut Vec::new(),
        "not approved",
        true,
    );
    let error = extract_error_msg(check_perm);
    assert!(error.contains("not approved"));

    // test owner later makes ownership of a single token public
    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: None,
        expires: Some(Expiration::AtTime(1000000)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token1: Token = json_load(&info_store, &nft1_key).unwrap();
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::ViewOwner,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());
    // test public approval when no address is given
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        None,
        PermissionType::ViewOwner,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());

    // test global approval for all tokens
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token2: Token = json_load(&info_store, &nft2_key).unwrap();
    let check_perm = check_permission(
        &deps,
        &block,
        &token2,
        "NFT2",
        Some(&bob_raw),
        PermissionType::ViewMetadata,
        &mut Vec::new(),
        "not approved",
        false,
    );
    let error = extract_error_msg(check_perm);
    assert!(error.contains("not approved"));
    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: None,
        view_owner: None,
        view_private_metadata: Some(AccessLevel::All),
        expires: Some(Expiration::AtTime(1000000)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token2: Token = json_load(&info_store, &nft2_key).unwrap();
    let check_perm = check_permission(
        &deps,
        &block,
        &token2,
        "NFT2",
        Some(&bob_raw),
        PermissionType::ViewMetadata,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());
    // test public approval when no address is given
    let check_perm = check_permission(
        &deps,
        &block,
        &token2,
        "NFT2",
        None,
        PermissionType::ViewMetadata,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());

    // test those global permissions having expired
    let block = BlockInfo {
        height: 1,
        time: 2000000,
        chain_id: "secret-2".to_string(),
    };
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::ViewOwner,
        &mut Vec::new(),
        "not approved",
        false,
    );
    let error = extract_error_msg(check_perm);
    assert!(error.contains("not approved"));
    let check_perm = check_permission(
        &deps,
        &block,
        &token2,
        "NFT2",
        Some(&bob_raw),
        PermissionType::ViewMetadata,
        &mut Vec::new(),
        "not approved",
        false,
    );
    let error = extract_error_msg(check_perm);
    assert!(error.contains("not approved"));

    let block = BlockInfo {
        height: 1,
        time: 1,
        chain_id: "secret-2".to_string(),
    };

    // test whitelisted approval on a token
    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: Some("NFT2".to_string()),
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::ApproveToken),
        expires: Some(Expiration::AtTime(5)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token2: Token = json_load(&info_store, &nft2_key).unwrap();
    let check_perm = check_permission(
        &deps,
        &block,
        &token2,
        "NFT2",
        Some(&bob_raw),
        PermissionType::Transfer,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());
    let check_perm = check_permission(
        &deps,
        &block,
        &token2,
        "NFT2",
        Some(&charlie_raw),
        PermissionType::Transfer,
        &mut Vec::new(),
        "not approved",
        false,
    );
    let error = extract_error_msg(check_perm);
    assert!(error.contains("not approved"));

    // test approval expired
    let block = BlockInfo {
        height: 1,
        time: 6,
        chain_id: "secret-2".to_string(),
    };
    let check_perm = check_permission(
        &deps,
        &block,
        &token2,
        "NFT2",
        Some(&bob_raw),
        PermissionType::Transfer,
        &mut Vec::new(),
        "not approved",
        false,
    );
    let error = extract_error_msg(check_perm);
    assert!(error.contains("Access to token NFT2 has expired"));

    // test owner access
    let check_perm = check_permission(
        &deps,
        &block,
        &token2,
        "NFT2",
        Some(&alice_raw),
        PermissionType::Transfer,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());

    // test whitelisted approval on all tokens
    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("charlie".to_string()),
        token_id: None,
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::All),
        expires: Some(Expiration::AtTime(7)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token1: Token = json_load(&info_store, &nft1_key).unwrap();
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::Transfer,
        &mut Vec::new(),
        "not approved",
        false,
    );
    let error = extract_error_msg(check_perm);
    assert!(error.contains("not approved"));
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&charlie_raw),
        PermissionType::Transfer,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());

    // test whitelisted ALL permission has expired
    let block = BlockInfo {
        height: 1,
        time: 7,
        chain_id: "secret-2".to_string(),
    };
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&charlie_raw),
        PermissionType::Transfer,
        &mut Vec::new(),
        "not approved",
        false,
    );
    let error = extract_error_msg(check_perm);
    assert!(error.contains("Access to all tokens of alice has expired"));

    let (init_result, mut deps) = init_helper_default();
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT1".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        public_metadata: Some(Metadata {
            name: Some("My1".to_string()),
            description: Some("Pub 1".to_string()),
            image: Some("URI 1".to_string()),
        }),
        private_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT2".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        public_metadata: Some(Metadata {
            name: Some("My2".to_string()),
            description: Some("Pub 2".to_string()),
            image: Some("URI 2".to_string()),
        }),
        private_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    // test whitelist approval expired, but global is good on a token
    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: Some("NFT1".to_string()),
        view_owner: None,
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: None,
        expires: Some(Expiration::AtTime(10)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: Some("NFT1".to_string()),
        view_owner: None,
        view_private_metadata: Some(AccessLevel::ApproveToken),
        expires: Some(Expiration::AtTime(1000)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let block = BlockInfo {
        height: 1,
        time: 100,
        chain_id: "secret-2".to_string(),
    };
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token1: Token = json_load(&info_store, &nft1_key).unwrap();
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::ViewMetadata,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());

    // test whitelist approval expired, but global is good on ALL tokens
    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: None,
        view_owner: None,
        view_private_metadata: Some(AccessLevel::All),
        transfer: None,
        expires: Some(Expiration::AtTime(10)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: None,
        view_owner: None,
        view_private_metadata: Some(AccessLevel::All),
        expires: Some(Expiration::AtTime(1000)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let block = BlockInfo {
        height: 1,
        time: 100,
        chain_id: "secret-2".to_string(),
    };
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token1: Token = json_load(&info_store, &nft1_key).unwrap();
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::ViewMetadata,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());

    // test whitelist approval is good, but global expired on a token
    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: Some("NFT1".to_string()),
        view_owner: None,
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: None,
        expires: Some(Expiration::AtTime(1000)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: Some("NFT1".to_string()),
        view_owner: None,
        view_private_metadata: Some(AccessLevel::ApproveToken),
        expires: Some(Expiration::AtTime(10)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let block = BlockInfo {
        height: 1,
        time: 100,
        chain_id: "secret-2".to_string(),
    };
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token1: Token = json_load(&info_store, &nft1_key).unwrap();
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::ViewMetadata,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());

    // test whitelist approval is good, but global expired on ALL tokens
    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: None,
        view_owner: None,
        view_private_metadata: Some(AccessLevel::All),
        transfer: None,
        expires: Some(Expiration::AtTime(10)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: None,
        view_owner: None,
        view_private_metadata: Some(AccessLevel::All),
        expires: Some(Expiration::AtTime(1000)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let block = BlockInfo {
        height: 1,
        time: 100,
        chain_id: "secret-2".to_string(),
    };
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token1: Token = json_load(&info_store, &nft1_key).unwrap();
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::ViewMetadata,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());

    let (init_result, mut deps) = init_helper_default();
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT1".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        public_metadata: Some(Metadata {
            name: Some("My1".to_string()),
            description: Some("Pub 1".to_string()),
            image: Some("URI 1".to_string()),
        }),
        private_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT2".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        public_metadata: Some(Metadata {
            name: Some("My2".to_string()),
            description: Some("Pub 2".to_string()),
            image: Some("URI 2".to_string()),
        }),
        private_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    // test bob has view owner approval on NFT1 and view metadata approval on ALL
    // while there is global view owner approval on ALL tokens and global view metadata
    // approval on NFT1
    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: Some(AccessLevel::All),
        transfer: None,
        expires: Some(Expiration::AtTime(100)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::All),
        view_private_metadata: Some(AccessLevel::ApproveToken),
        expires: Some(Expiration::AtTime(10)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let block = BlockInfo {
        height: 1,
        time: 1,
        chain_id: "secret-2".to_string(),
    };
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token1: Token = json_load(&info_store, &nft1_key).unwrap();
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::Transfer,
        &mut Vec::new(),
        "not approved",
        false,
    );
    let error = extract_error_msg(check_perm);
    assert!(error.contains("not approved"));
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::ViewOwner,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::ViewMetadata,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());

    // now check where the global approvals expired
    let block = BlockInfo {
        height: 1,
        time: 50,
        chain_id: "secret-2".to_string(),
    };
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::ViewOwner,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&bob_raw),
        PermissionType::ViewMetadata,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());

    // throw a charlie transfer approval and a view meta token approval in the mix
    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("charlie".to_string()),
        token_id: None,
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::All),
        expires: Some(Expiration::AtTime(100)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("charlie".to_string()),
        token_id: Some("NFT1".to_string()),
        view_owner: None,
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: None,
        expires: Some(Expiration::AtTime(100)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token1: Token = json_load(&info_store, &nft1_key).unwrap();
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&charlie_raw),
        PermissionType::Transfer,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());
    let check_perm = check_permission(
        &deps,
        &block,
        &token1,
        "NFT1",
        Some(&charlie_raw),
        PermissionType::ViewMetadata,
        &mut Vec::new(),
        "not approved",
        false,
    );
    assert!(check_perm.is_ok());
}
