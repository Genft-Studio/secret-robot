use crate::unittest_helpers::{init_helper_with_config, extract_error_msg, set_contract_status};
use crate::msg::{HandleMsg, AccessLevel, ContractStatus};
use crate::contract::handle;
use cosmwasm_std::testing::mock_env;
use cosmwasm_std::{HumanAddr, CanonicalAddr, Api, Binary};
use crate::token::{Metadata, Token};
use crate::expiration::Expiration;
use crate::state::{PermissionType, PREFIX_ALL_PERMISSIONS, Permission, json_load, PREFIX_INFOS, PREFIX_PUB_META, load, PREFIX_PRIV_META, may_load, PREFIX_AUTHLIST, AuthList};
use cosmwasm_storage::ReadonlyPrefixedStorage;

// test owner setting global approvals
#[test]
fn test_set_global_approval() {
    let (init_result, mut deps) =
        init_helper_with_config(true, false, false, false, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // test token does not exist when supply is public
    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::All),
        view_private_metadata: None,
        expires: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("Token ID: NFT1 not found"));

    let (init_result, mut deps) =
        init_helper_with_config(false, false, false, false, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    // test token does not exist when supply is private
    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::All),
        view_private_metadata: None,
        expires: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("You do not own token NFT1"));

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

    // test trying to set approval when status does not allow
    set_contract_status(&mut deps, ContractStatus::StopAll);

    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::All),
        view_private_metadata: None,
        expires: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("The contract admin has temporarily disabled this action"));

    // setting approval is ok even during StopTransactions status
    set_contract_status(&mut deps, ContractStatus::StopTransactions);

    // only allow the owner to use SetGlobalApproval
    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: None,
        expires: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("You do not own token NFT1"));

    // try approving a token without specifying which token
    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: None,
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: None,
        expires: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains(
        "Attempted to grant/revoke permission for a token, but did not specify a token ID"
    ));

    // try revoking a token approval without specifying which token
    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: None,
        view_owner: Some(AccessLevel::RevokeToken),
        view_private_metadata: None,
        expires: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains(
        "Attempted to grant/revoke permission for a token, but did not specify a token ID"
    ));

    // sanity check
    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::All),
        view_private_metadata: Some(AccessLevel::ApproveToken),
        expires: Some(Expiration::AtTime(1000000)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let global_raw = CanonicalAddr(Binary::from(b"public"));
    let alice_raw = deps
        .api
        .canonical_address(&HumanAddr("alice".to_string()))
        .unwrap();
    let alice_key = alice_raw.as_slice();
    let view_owner_idx = PermissionType::ViewOwner.to_usize();
    let view_meta_idx = PermissionType::ViewMetadata.to_usize();
    let transfer_idx = PermissionType::Transfer.to_usize();
    // confirm ALL permission
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
    assert_eq!(all_perm.len(), 1);
    let global_perm = all_perm.iter().find(|p| p.address == global_raw).unwrap();
    assert_eq!(
        global_perm.expirations[view_owner_idx],
        Some(Expiration::AtTime(1000000))
    );
    assert_eq!(global_perm.expirations[view_meta_idx], None);
    assert_eq!(global_perm.expirations[transfer_idx], None);
    // confirm NFT1 permissions and that the token data did not get modified
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let nft1_key = 0u32.to_le_bytes();
    let token: Token = json_load(&info_store, &nft1_key).unwrap();
    assert_eq!(token.owner, alice_raw);
    assert!(token.unwrapped);
    let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
    let pub_meta: Metadata = load(&pub_store, &nft1_key).unwrap();
    assert_eq!(pub_meta.name, Some("My1".to_string()));
    assert_eq!(pub_meta.description, Some("Pub 1".to_string()));
    assert_eq!(pub_meta.image, Some("URI 1".to_string()));
    let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
    let priv_meta: Option<Metadata> = may_load(&priv_store, &nft1_key).unwrap();
    assert!(priv_meta.is_none());
    assert_eq!(token.permissions.len(), 1);
    let global_tok_perm = token
        .permissions
        .iter()
        .find(|p| p.address == global_raw)
        .unwrap();
    assert_eq!(
        global_tok_perm.expirations[view_meta_idx],
        Some(Expiration::AtTime(1000000))
    );
    assert_eq!(global_tok_perm.expirations[transfer_idx], None);
    assert_eq!(global_tok_perm.expirations[view_owner_idx], None);
    // confirm AuthLists has public with NFT1 permission
    let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
    let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
    assert_eq!(auth_list.len(), 1);
    let global_auth = auth_list.iter().find(|a| a.address == global_raw).unwrap();
    assert_eq!(global_auth.tokens[view_meta_idx].len(), 1);
    assert!(global_auth.tokens[view_meta_idx].contains(&0u32));
    assert!(global_auth.tokens[transfer_idx].is_empty());
    assert!(global_auth.tokens[view_owner_idx].is_empty());

    // bob approvals to make sure whitelisted addresses don't break
    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::All),
        view_private_metadata: None,
        transfer: Some(AccessLevel::ApproveToken),
        expires: Some(Expiration::AtTime(1000000)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let bob_raw = deps
        .api
        .canonical_address(&HumanAddr("bob".to_string()))
        .unwrap();
    // confirm ALL permission
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
    assert_eq!(all_perm.len(), 2);
    let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
    assert_eq!(
        bob_oper_perm.expirations[view_owner_idx],
        Some(Expiration::AtTime(1000000))
    );
    assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
    assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
    let global_perm = all_perm.iter().find(|p| p.address == global_raw).unwrap();
    assert_eq!(
        global_perm.expirations[view_owner_idx],
        Some(Expiration::AtTime(1000000))
    );
    assert_eq!(global_perm.expirations[view_meta_idx], None);
    assert_eq!(global_perm.expirations[transfer_idx], None);
    // confirm NFT1 permissions
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token: Token = json_load(&info_store, &nft1_key).unwrap();
    assert_eq!(token.permissions.len(), 2);
    let bob_tok_perm = token
        .permissions
        .iter()
        .find(|p| p.address == bob_raw)
        .unwrap();
    assert_eq!(
        bob_tok_perm.expirations[transfer_idx],
        Some(Expiration::AtTime(1000000))
    );
    assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
    assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
    assert_eq!(
        global_tok_perm.expirations[view_meta_idx],
        Some(Expiration::AtTime(1000000))
    );
    assert_eq!(global_tok_perm.expirations[transfer_idx], None);
    assert_eq!(global_tok_perm.expirations[view_owner_idx], None);
    // confirm AuthLists has bob with NFT1 permission
    let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
    let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
    assert_eq!(auth_list.len(), 2);
    let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
    assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
    assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
    assert!(bob_auth.tokens[view_meta_idx].is_empty());
    assert!(bob_auth.tokens[view_owner_idx].is_empty());
    let global_auth = auth_list.iter().find(|a| a.address == global_raw).unwrap();
    assert_eq!(global_auth.tokens[view_meta_idx].len(), 1);
    assert!(global_auth.tokens[view_meta_idx].contains(&0u32));
    assert!(global_auth.tokens[transfer_idx].is_empty());
    assert!(global_auth.tokens[view_owner_idx].is_empty());

    // confirm ALL permission
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
    assert_eq!(all_perm.len(), 2);
    let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
    assert_eq!(
        bob_oper_perm.expirations[view_owner_idx],
        Some(Expiration::AtTime(1000000))
    );
    assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
    assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
    let global_perm = all_perm.iter().find(|p| p.address == global_raw).unwrap();
    assert_eq!(
        global_perm.expirations[view_owner_idx],
        Some(Expiration::AtTime(1000000))
    );
    assert_eq!(global_perm.expirations[view_meta_idx], None);
    assert_eq!(global_perm.expirations[transfer_idx], None);
    // confirm NFT1 permissions
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token: Token = json_load(&info_store, &nft1_key).unwrap();
    assert_eq!(token.permissions.len(), 2);
    let bob_tok_perm = token
        .permissions
        .iter()
        .find(|p| p.address == bob_raw)
        .unwrap();
    assert_eq!(
        bob_tok_perm.expirations[transfer_idx],
        Some(Expiration::AtTime(1000000))
    );
    assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
    assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
    assert_eq!(
        global_tok_perm.expirations[view_meta_idx],
        Some(Expiration::AtTime(1000000))
    );
    assert_eq!(global_tok_perm.expirations[transfer_idx], None);
    assert_eq!(global_tok_perm.expirations[view_owner_idx], None);
    // confirm AuthLists has bob with NFT1 permission
    let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
    let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
    assert_eq!(auth_list.len(), 2);
    let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
    assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
    assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
    assert!(bob_auth.tokens[view_meta_idx].is_empty());
    assert!(bob_auth.tokens[view_owner_idx].is_empty());
    let global_auth = auth_list.iter().find(|a| a.address == global_raw).unwrap();
    assert_eq!(global_auth.tokens[view_meta_idx].len(), 1);
    assert!(global_auth.tokens[view_meta_idx].contains(&0u32));
    assert!(global_auth.tokens[transfer_idx].is_empty());
    assert!(global_auth.tokens[view_owner_idx].is_empty());

    // test revoking global approval
    let handle_msg = HandleMsg::SetGlobalApproval {
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::All),
        view_private_metadata: Some(AccessLevel::None),
        expires: Some(Expiration::AtTime(1000000)),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    // confirm ALL permission
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
    assert_eq!(all_perm.len(), 2);
    let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
    assert_eq!(
        bob_oper_perm.expirations[view_owner_idx],
        Some(Expiration::AtTime(1000000))
    );
    assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
    assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
    let global_perm = all_perm.iter().find(|p| p.address == global_raw).unwrap();
    assert_eq!(
        global_perm.expirations[view_owner_idx],
        Some(Expiration::AtTime(1000000))
    );
    assert_eq!(global_perm.expirations[view_meta_idx], None);
    assert_eq!(global_perm.expirations[transfer_idx], None);
    // confirm NFT1 permissions
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token: Token = json_load(&info_store, &nft1_key).unwrap();
    assert_eq!(token.permissions.len(), 1);
    let bob_tok_perm = token
        .permissions
        .iter()
        .find(|p| p.address == bob_raw)
        .unwrap();
    assert_eq!(
        bob_tok_perm.expirations[transfer_idx],
        Some(Expiration::AtTime(1000000))
    );
    assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
    assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
    let global_tok_perm = token.permissions.iter().find(|p| p.address == global_raw);
    assert!(global_tok_perm.is_none());
    // confirm AuthLists has bob with NFT1 permission
    let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
    let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
    assert_eq!(auth_list.len(), 1);
    let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
    assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
    assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
    assert!(bob_auth.tokens[view_meta_idx].is_empty());
    assert!(bob_auth.tokens[view_owner_idx].is_empty());
    let global_auth = auth_list.iter().find(|a| a.address == global_raw);
    assert!(global_auth.is_none());
}
