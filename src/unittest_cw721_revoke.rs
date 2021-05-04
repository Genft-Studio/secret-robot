use crate::unittest_helpers::{init_helper_with_config, extract_error_msg, init_helper_default, set_contract_status};
use crate::msg::{HandleMsg, ContractStatus, AccessLevel};
use cosmwasm_std::{HumanAddr, Env, BlockInfo, MessageInfo, Api};
use crate::contract::handle;
use cosmwasm_std::testing::{mock_env, MOCK_CONTRACT_ADDR};
use crate::token::{Metadata, Token};
use crate::expiration::Expiration;
use crate::state::{PermissionType, PREFIX_ALL_PERMISSIONS, Permission, json_load, PREFIX_INFOS, PREFIX_PRIV_META, load, PREFIX_PUB_META, may_load, PREFIX_AUTHLIST, AuthList, json_may_load};
use cosmwasm_storage::ReadonlyPrefixedStorage;

#[test]
fn test_cw721_revoke() {
    let (init_result, mut deps) =
        init_helper_with_config(true, false, false, false, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // test token does not exist when supply is public
    let handle_msg = HandleMsg::Revoke {
        spender: HumanAddr("bob".to_string()),
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("Token ID: MyNFT not found"));

    let (init_result, mut deps) = init_helper_default();
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // test token does not exist when supply is private
    let handle_msg = HandleMsg::Revoke {
        spender: HumanAddr("bob".to_string()),
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(
        error.contains("Not authorized to grant/revoke transfer permission for token MyNFT")
    );

    let handle_msg = HandleMsg::MintNft {
        token_id: Some("MyNFT".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: Some(Metadata {
            name: Some("MyNFT".to_string()),
            description: Some("metadata".to_string()),
            image: Some("uri".to_string()),
        }),
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    // test contract status does not allow
    set_contract_status(&mut deps, ContractStatus::StopAll);

    let handle_msg = HandleMsg::Revoke {
        spender: HumanAddr("bob".to_string()),
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("The contract admin has temporarily disabled this action"));

    set_contract_status(&mut deps, ContractStatus::StopTransactions);

    // test unauthorized address attempt
    let handle_msg = HandleMsg::Revoke {
        spender: HumanAddr("bob".to_string()),
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(
        error.contains("Not authorized to grant/revoke transfer permission for token MyNFT")
    );

    // test expired operator attempt
    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: None,
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::All),
        expires: Some(Expiration::AtTime(1000000)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("charlie".to_string()),
        token_id: Some("MyNFT".to_string()),
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::All),
        expires: Some(Expiration::AtTime(500000)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::Revoke {
        spender: HumanAddr("charlie".to_string()),
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let handle_result = handle(
        &mut deps,
        Env {
            block: BlockInfo {
                height: 100,
                time: 2000000,
                chain_id: "cosmos-testnet-14002".to_string(),
            },
            message: MessageInfo {
                sender: HumanAddr("bob".to_string()),
                sent_funds: vec![],
            },
            contract: cosmwasm_std::ContractInfo {
                address: HumanAddr::from(MOCK_CONTRACT_ADDR),
            },
            contract_key: Some("".to_string()),
            contract_code_hash: "".to_string(),
        },
        handle_msg,
    );
    let error = extract_error_msg(handle_result);
    assert!(error.contains("Transfer authority for all tokens of alice has expired"));

    let tok_key = 0u32.to_le_bytes();
    let tok2_key = 1u32.to_le_bytes();
    let tok3_key = 2u32.to_le_bytes();
    let charlie_raw = deps
        .api
        .canonical_address(&HumanAddr("charlie".to_string()))
        .unwrap();
    let david_raw = deps
        .api
        .canonical_address(&HumanAddr("david".to_string()))
        .unwrap();
    let alice_raw = deps
        .api
        .canonical_address(&HumanAddr("alice".to_string()))
        .unwrap();
    let alice_key = alice_raw.as_slice();
    let view_owner_idx = PermissionType::ViewOwner.to_usize();
    let view_meta_idx = PermissionType::ViewMetadata.to_usize();
    let transfer_idx = PermissionType::Transfer.to_usize();

    // test operator tries to revoke permission from another operator
    let handle_msg = HandleMsg::Revoke {
        spender: HumanAddr("charlie".to_string()),
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let handle_result = handle(
        &mut deps,
        Env {
            block: BlockInfo {
                height: 100,
                time: 1000,
                chain_id: "cosmos-testnet-14002".to_string(),
            },
            message: MessageInfo {
                sender: HumanAddr("bob".to_string()),
                sent_funds: vec![],
            },
            contract: cosmwasm_std::ContractInfo {
                address: HumanAddr::from(MOCK_CONTRACT_ADDR),
            },
            contract_key: Some("".to_string()),
            contract_code_hash: "".to_string(),
        },
        handle_msg,
    );
    let error = extract_error_msg(handle_result);
    assert!(error.contains("Can not revoke transfer permission from an existing operator"));

    // sanity check:  operator revokes approval from an expired operator will delete
    // the expired ALL permission
    let handle_msg = HandleMsg::Revoke {
        spender: HumanAddr("charlie".to_string()),
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let result = handle(
        &mut deps,
        Env {
            block: BlockInfo {
                height: 100,
                time: 750000,
                chain_id: "cosmos-testnet-14002".to_string(),
            },
            message: MessageInfo {
                sender: HumanAddr("bob".to_string()),
                sent_funds: vec![],
            },
            contract: cosmwasm_std::ContractInfo {
                address: HumanAddr::from(MOCK_CONTRACT_ADDR),
            },
            contract_key: Some("".to_string()),
            contract_code_hash: "".to_string(),
        },
        handle_msg,
    );
    assert!(result.is_ok());

    // confirm charlie's expired ALL permission was removed
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
    assert_eq!(all_perm.len(), 1);
    assert!(all_perm.iter().find(|p| p.address == charlie_raw).is_none());
    // confirm token permission is still empty
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token: Token = json_load(&info_store, &tok_key).unwrap();
    assert!(token.permissions.is_empty());
    let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
    let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
    assert_eq!(priv_meta.name, Some("MyNFT".to_string()));
    assert_eq!(priv_meta.description, Some("metadata".to_string()));
    assert_eq!(priv_meta.image, Some("uri".to_string()));
    let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
    let pub_meta: Option<Metadata> = may_load(&pub_store, &tok_key).unwrap();
    assert!(pub_meta.is_none());
    // confirm AuthList is still empty
    let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
    let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
    assert!(auth_list.is_none());

    // sanity check: operator approves, then revokes
    let handle_msg = HandleMsg::Approve {
        spender: HumanAddr("charlie".to_string()),
        token_id: "MyNFT".to_string(),
        expires: Some(Expiration::AtHeight(200)),
        padding: None,
    };
    let result = handle(
        &mut deps,
        Env {
            block: BlockInfo {
                height: 100,
                time: 100,
                chain_id: "cosmos-testnet-14002".to_string(),
            },
            message: MessageInfo {
                sender: HumanAddr("bob".to_string()),
                sent_funds: vec![],
            },
            contract: cosmwasm_std::ContractInfo {
                address: HumanAddr::from(MOCK_CONTRACT_ADDR),
            },
            contract_key: Some("".to_string()),
            contract_code_hash: "".to_string(),
        },
        handle_msg,
    );
    assert!(result.is_ok());

    // confirm charlie does not have ALL permission
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
    assert_eq!(all_perm.len(), 1);
    assert!(all_perm.iter().find(|p| p.address == charlie_raw).is_none());
    // confirm token permission added charlie
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token: Token = json_load(&info_store, &tok_key).unwrap();
    assert_eq!(token.permissions.len(), 1);
    let charlie_tok_perm = token
        .permissions
        .iter()
        .find(|p| p.address == charlie_raw)
        .unwrap();
    assert_eq!(
        charlie_tok_perm.expirations[transfer_idx],
        Some(Expiration::AtHeight(200))
    );
    assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
    assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
    let handle_msg = HandleMsg::Revoke {
        spender: HumanAddr("charlie".to_string()),
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let result = handle(
        &mut deps,
        Env {
            block: BlockInfo {
                height: 100,
                time: 100,
                chain_id: "cosmos-testnet-14002".to_string(),
            },
            message: MessageInfo {
                sender: HumanAddr("bob".to_string()),
                sent_funds: vec![],
            },
            contract: cosmwasm_std::ContractInfo {
                address: HumanAddr::from(MOCK_CONTRACT_ADDR),
            },
            contract_key: Some("".to_string()),
            contract_code_hash: "".to_string(),
        },
        handle_msg,
    );
    assert!(result.is_ok());

    // confirm charlie does not have ALL permission
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
    assert_eq!(all_perm.len(), 1);
    assert!(all_perm.iter().find(|p| p.address == charlie_raw).is_none());
    // confirm token permission removed charlie
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token: Token = json_load(&info_store, &tok_key).unwrap();
    assert_eq!(token.owner, alice_raw);
    assert!(token.unwrapped);
    let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
    let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
    assert_eq!(priv_meta.name, Some("MyNFT".to_string()));
    assert_eq!(priv_meta.description, Some("metadata".to_string()));
    assert_eq!(priv_meta.image, Some("uri".to_string()));
    let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
    let pub_meta: Option<Metadata> = may_load(&pub_store, &tok_key).unwrap();
    assert!(pub_meta.is_none());
    assert!(token.permissions.is_empty());
    // confirm AuthList removed charlie
    let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
    let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
    assert!(auth_list.is_none());

    // verify revoking a non-existent permission does not break anything
    let handle_msg = HandleMsg::Revoke {
        spender: HumanAddr("charlie".to_string()),
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    // confirm charlie does not have ALL permission
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
    assert_eq!(all_perm.len(), 1);
    assert!(all_perm.iter().find(|p| p.address == charlie_raw).is_none());
    // confirm token does not list charlie
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token: Token = json_load(&info_store, &tok_key).unwrap();
    assert_eq!(token.owner, alice_raw);
    assert!(token.unwrapped);
    let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
    let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
    assert_eq!(priv_meta.name, Some("MyNFT".to_string()));
    assert_eq!(priv_meta.description, Some("metadata".to_string()));
    assert_eq!(priv_meta.image, Some("uri".to_string()));
    let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
    let pub_meta: Option<Metadata> = may_load(&pub_store, &tok_key).unwrap();
    assert!(pub_meta.is_none());
    assert!(token.permissions.is_empty());
    // confirm AuthList doesn not contain charlie
    let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
    let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
    assert!(auth_list.is_none());

    // sanity check:  owner revokes token approval for an operator with only that one token
    let handle_msg = HandleMsg::Revoke {
        spender: HumanAddr("bob".to_string()),
        token_id: "MyNFT".to_string(),
        padding: None,
    };
    let result = handle(
        &mut deps,
        Env {
            block: BlockInfo {
                height: 100,
                time: 100,
                chain_id: "cosmos-testnet-14002".to_string(),
            },
            message: MessageInfo {
                sender: HumanAddr("alice".to_string()),
                sent_funds: vec![],
            },
            contract: cosmwasm_std::ContractInfo {
                address: HumanAddr::from(MOCK_CONTRACT_ADDR),
            },
            contract_key: Some("".to_string()),
            contract_code_hash: "".to_string(),
        },
        handle_msg,
    );
    assert!(result.is_ok());

    // confirm bob's ALL permission was removed
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let all_perm: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
    assert!(all_perm.is_none());
    // confirm token permission is empty
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token: Token = json_load(&info_store, &tok_key).unwrap();
    assert_eq!(token.owner, alice_raw);
    assert!(token.unwrapped);
    let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
    let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
    assert_eq!(priv_meta.name, Some("MyNFT".to_string()));
    assert_eq!(priv_meta.description, Some("metadata".to_string()));
    assert_eq!(priv_meta.image, Some("uri".to_string()));
    let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
    let pub_meta: Option<Metadata> = may_load(&pub_store, &tok_key).unwrap();
    assert!(pub_meta.is_none());
    assert!(token.permissions.is_empty());
    // confirm AuthList does not contain bob
    let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
    let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
    assert!(auth_list.is_none());

    // used to test auto-setting individual token permissions when only one token
    // of many is revoked from an operator
    set_contract_status(&mut deps, ContractStatus::Normal);

    let handle_msg = HandleMsg::MintNft {
        token_id: Some("MyNFT2".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: Some(Metadata {
            name: Some("MyNFT2".to_string()),
            description: Some("metadata2".to_string()),
            image: Some("uri2".to_string()),
        }),
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::MintNft {
        token_id: Some("MyNFT3".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: Some(Metadata {
            name: Some("MyNFT3".to_string()),
            description: Some("metadata3".to_string()),
            image: Some("uri3".to_string()),
        }),
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("david".to_string()),
        token_id: None,
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::All),
        expires: Some(Expiration::Never),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    // confirm david is an operator
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
    assert_eq!(all_perm.len(), 1);
    let david_oper_perm = all_perm.iter().find(|p| p.address == david_raw).unwrap();
    assert_eq!(
        david_oper_perm.expirations[transfer_idx],
        Some(Expiration::Never)
    );
    assert_eq!(david_oper_perm.expirations[view_meta_idx], None);
    assert_eq!(david_oper_perm.expirations[view_owner_idx], None);
    let handle_msg = HandleMsg::Revoke {
        spender: HumanAddr("david".to_string()),
        token_id: "MyNFT2".to_string(),
        padding: None,
    };
    let result = handle(
        &mut deps,
        Env {
            block: BlockInfo {
                height: 100,
                time: 100,
                chain_id: "cosmos-testnet-14002".to_string(),
            },
            message: MessageInfo {
                sender: HumanAddr("alice".to_string()),
                sent_funds: vec![],
            },
            contract: cosmwasm_std::ContractInfo {
                address: HumanAddr::from(MOCK_CONTRACT_ADDR),
            },
            contract_key: Some("".to_string()),
            contract_code_hash: "".to_string(),
        },
        handle_msg,
    );
    assert!(result.is_ok());

    // confirm david's ALL permission was removed
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let all_perm: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
    assert!(all_perm.is_none());
    // confirm MyNFT token permission added david with ALL permission's expiration
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token: Token = json_load(&info_store, &tok_key).unwrap();
    assert_eq!(token.permissions.len(), 1);
    let david_tok_perm = token
        .permissions
        .iter()
        .find(|p| p.address == david_raw)
        .unwrap();
    assert_eq!(
        david_tok_perm.expirations[transfer_idx],
        Some(Expiration::Never)
    );
    assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
    assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
    // confirm MyNFT2 token permission does not contain david
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token: Token = json_load(&info_store, &tok2_key).unwrap();
    assert!(token.permissions.is_empty());
    assert_eq!(token.owner, alice_raw);
    assert!(token.unwrapped);
    let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
    let priv_meta: Metadata = load(&priv_store, &tok2_key).unwrap();
    assert_eq!(priv_meta.name, Some("MyNFT2".to_string()));
    assert_eq!(priv_meta.description, Some("metadata2".to_string()));
    assert_eq!(priv_meta.image, Some("uri2".to_string()));
    let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
    let pub_meta: Option<Metadata> = may_load(&pub_store, &tok2_key).unwrap();
    assert!(pub_meta.is_none());
    // confirm MyNFT3 token permission added david with ALL permission's expiration
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token: Token = json_load(&info_store, &tok3_key).unwrap();
    assert_eq!(token.permissions.len(), 1);
    let david_tok_perm = token
        .permissions
        .iter()
        .find(|p| p.address == david_raw)
        .unwrap();
    assert_eq!(
        david_tok_perm.expirations[transfer_idx],
        Some(Expiration::Never)
    );
    assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
    assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
    // confirm AuthList added david
    let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
    let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
    assert_eq!(auth_list.len(), 1);
    let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
    assert_eq!(david_auth.tokens[transfer_idx].len(), 2);
    assert!(david_auth.tokens[transfer_idx].contains(&0u32));
    assert!(!david_auth.tokens[transfer_idx].contains(&1u32));
    assert!(david_auth.tokens[transfer_idx].contains(&2u32));
    assert!(david_auth.tokens[view_meta_idx].is_empty());
    assert!(david_auth.tokens[view_owner_idx].is_empty());
}
