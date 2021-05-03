use crate::unittest_helpers::{init_helper_with_config, extract_error_msg, set_contract_status};
use crate::msg::{HandleMsg, ContractStatus, AccessLevel, Burn, TxAction};
use cosmwasm_std::{HumanAddr, Api, Extern};
use crate::contract::handle;
use cosmwasm_std::testing::{mock_env, MockStorage, MockApi, MockQuerier};
use crate::token::{Metadata, Token};
use crate::state::{PermissionType, load, TOKENS_KEY, PREFIX_MAP_TO_INDEX, may_load, PREFIX_INFOS, json_may_load, PREFIX_PRIV_META, json_load, AuthList, PREFIX_OWNED, PREFIX_AUTHLIST, get_txs, PREFIX_PUB_META, PREFIX_MAP_TO_ID};
use std::collections::HashSet;
use cosmwasm_storage::ReadonlyPrefixedStorage;
use crate::expiration::Expiration;

#[test]
fn test_batch_burn_when_status_prevents_it() {
    let (init_result, mut deps) =
        init_helper_with_config(false, false, false, false, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );
    mint_nft1_alice_grant_bob_charlie(&mut deps);

    // test burn when status prevents it
    set_contract_status(&mut deps, ContractStatus::StopTransactions);

    let handle_msg = HandleMsg::BurnNft {
        token_id: "NFT1".to_string(),
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("The contract admin has temporarily disabled this action"));

    set_contract_status(&mut deps, ContractStatus::Normal);
}

#[test]
fn test_batch_burn_when_diabled_for_token() {
    let (init_result, mut deps) =
        init_helper_with_config(false, false, false, false, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    mint_nft1_alice_grant_bob_charlie(&mut deps);

    let handle_msg = HandleMsg::BurnNft {
        token_id: "NFT1".to_string(),
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("Burn functionality is not enabled for this token"));
}

#[test]
fn test_batch_burn_duplicate() {
    let (init_result, mut deps) =
        init_helper_with_config(false, false, false, false, false, false, true);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    mint_nft1_alice_grant_bob_charlie(&mut deps);
    mint_nft2_alice_grant_charlie(&mut deps);
    mint_nft3_alice_grant_bob(&mut deps);
    mint_nft4_bob_grant_alice(&mut deps);
    mint_nft5_bob_grant_alice_charlie(&mut deps);
    mint_nft6_bob_grant_alice(&mut deps);
    mint_nft7_charlie_grant_alice(&mut deps);
    mint_nft8_charlie(&mut deps);
    grant_all(&mut deps, "charlie", "bob");

    // test bob burning a list, but trying to burn the same token twice
    let burns = vec![
        Burn {
            token_ids: vec!["NFT1".to_string(), "NFT3".to_string()],
            memo: None,
        },
        Burn {
            token_ids: vec!["NFT6".to_string()],
            memo: None,
        },
        Burn {
            token_ids: vec!["NFT6".to_string()],
            memo: None,
        },
        Burn {
            token_ids: vec!["NFT8".to_string()],
            memo: Some("Phew!".to_string()),
        },
    ];
    let handle_msg = HandleMsg::BatchBurnNft {
        burns,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    // because the token no longer exists after burning it, it will say you are not
    // authorized if supply is private, and token not found if public
    assert!(error.contains("You are not authorized to perform this action on token NFT6"));
}

#[test]
fn test_batch_burn_unauthorized() {
    let (init_result, mut deps) =
        init_helper_with_config(false, false, false, false, false, false, true);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );

    mint_nft1_alice_grant_bob_charlie(&mut deps);
    mint_nft2_alice_grant_charlie(&mut deps);
    mint_nft3_alice_grant_bob(&mut deps);
    mint_nft4_bob_grant_alice(&mut deps);
    mint_nft5_bob_grant_alice_charlie(&mut deps);
    mint_nft6_bob_grant_alice(&mut deps);
    mint_nft7_charlie_grant_alice(&mut deps);
    mint_nft8_charlie(&mut deps);
    grant_all(&mut deps, "charlie", "bob");

    // test bob burning a list, but one is not authorized
    let burns = vec![
        Burn {
            token_ids: vec![
                "NFT1".to_string(),
                "NFT3".to_string(),
                "NFT6".to_string(),
                "NFT2".to_string(),
            ],
            memo: None,
        },
        Burn {
            token_ids: vec!["NFT8".to_string()],
            memo: Some("Phew!".to_string()),
        },
    ];
    let handle_msg = HandleMsg::BatchBurnNft {
        burns,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("You are not authorized to perform this action on token NFT2"));
}
#[test]
fn test_batch_burn() {
    // set up for batch burn test
    let (init_result, mut deps) =
        init_helper_with_config(false, false, true, false, false, false, true);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );
    mint_nft1_alice_grant_bob_charlie(&mut deps);
    mint_nft2_alice_grant_charlie(&mut deps);
    mint_nft3_alice_grant_bob(&mut deps);
    mint_nft4_bob_grant_alice(&mut deps);
    mint_nft5_bob_grant_alice_charlie(&mut deps);
    mint_nft6_bob_grant_alice(&mut deps);
    mint_nft7_charlie_grant_alice(&mut deps);
    mint_nft8_charlie(&mut deps);

    grant_all(&mut deps, "charlie", "bob");

    // test bob burning NFT1 and 3 from alice with token permission,
    // burning NFT6 as the owner,
    // and burning NFT7 and NFT8 with ALL permission
    let burns = vec![
        Burn {
            token_ids: vec!["NFT1".to_string()],
            memo: None,
        },
        Burn {
            token_ids: vec!["NFT3".to_string()],
            memo: None,
        },
        Burn {
            token_ids: vec!["NFT6".to_string(), "NFT7".to_string(), "NFT8".to_string()],
            memo: Some("Phew!".to_string()),
        },
    ];
    let handle_msg = HandleMsg::BatchBurnNft {
        burns,
        padding: None,
    };
    let _handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);

    let view_owner_idx = PermissionType::ViewOwner.to_usize();
    let view_meta_idx = PermissionType::ViewMetadata.to_usize();
    let transfer_idx = PermissionType::Transfer.to_usize();
    let tok1_key = 0u32.to_le_bytes();
    let tok2_key = 1u32.to_le_bytes();
    let tok3_key = 2u32.to_le_bytes();
    let tok6_key = 5u32.to_le_bytes();
    let tok7_key = 6u32.to_le_bytes();
    let tok8_key = 6u32.to_le_bytes();
    let alice_raw = deps
        .api
        .canonical_address(&HumanAddr("alice".to_string()))
        .unwrap();
    let alice_key = alice_raw.as_slice();
    let bob_raw = deps
        .api
        .canonical_address(&HumanAddr("bob".to_string()))
        .unwrap();
    let bob_key = bob_raw.as_slice();
    let charlie_raw = deps
        .api
        .canonical_address(&HumanAddr("charlie".to_string()))
        .unwrap();
    let charlie_key = charlie_raw.as_slice();
    // confirm correct tokens were removed from the maps
    let tokens: HashSet<String> = load(&deps.storage, TOKENS_KEY).unwrap();
    assert_eq!(tokens.len(), 3);
    assert!(!tokens.contains("NFT1"));
    assert!(tokens.contains("NFT2"));
    assert!(!tokens.contains("NFT3"));
    assert!(tokens.contains("NFT4"));
    assert!(tokens.contains("NFT5"));
    assert!(!tokens.contains("NFT6"));
    assert!(!tokens.contains("NFT7"));
    assert!(!tokens.contains("NFT8"));
    let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
    let index: Option<u32> = may_load(&map2idx, "NFT1".as_bytes()).unwrap();
    assert!(index.is_none());
    let index: Option<u32> = may_load(&map2idx, "NFT2".as_bytes()).unwrap();
    assert!(index.is_some());
    let index: Option<u32> = may_load(&map2idx, "NFT3".as_bytes()).unwrap();
    assert!(index.is_none());
    let index: Option<u32> = may_load(&map2idx, "NFT4".as_bytes()).unwrap();
    assert!(index.is_some());
    let index: Option<u32> = may_load(&map2idx, "NFT5".as_bytes()).unwrap();
    assert!(index.is_some());
    let index: Option<u32> = may_load(&map2idx, "NFT6".as_bytes()).unwrap();
    assert!(index.is_none());
    let index: Option<u32> = may_load(&map2idx, "NFT7".as_bytes()).unwrap();
    assert!(index.is_none());
    let index: Option<u32> = may_load(&map2idx, "NFT8".as_bytes()).unwrap();
    assert!(index.is_none());
    let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
    let id: Option<String> = may_load(&map2id, &0u32.to_le_bytes()).unwrap();
    assert!(id.is_none());
    let id: Option<String> = may_load(&map2id, &1u32.to_le_bytes()).unwrap();
    assert!(id.is_some());
    let id: Option<String> = may_load(&map2id, &2u32.to_le_bytes()).unwrap();
    assert!(id.is_none());
    let id: Option<String> = may_load(&map2id, &3u32.to_le_bytes()).unwrap();
    assert!(id.is_some());
    let id: Option<String> = may_load(&map2id, &4u32.to_le_bytes()).unwrap();
    assert!(id.is_some());
    let id: Option<String> = may_load(&map2id, &5u32.to_le_bytes()).unwrap();
    assert!(id.is_none());
    let id: Option<String> = may_load(&map2id, &6u32.to_le_bytes()).unwrap();
    assert!(id.is_none());
    let id: Option<String> = may_load(&map2id, &7u32.to_le_bytes()).unwrap();
    assert!(id.is_none());
    // confirm token infos were deleted from storage
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token: Option<Token> = json_may_load(&info_store, &tok1_key).unwrap();
    assert!(token.is_none());
    let token: Option<Token> = json_may_load(&info_store, &tok3_key).unwrap();
    assert!(token.is_none());
    let token: Option<Token> = json_may_load(&info_store, &tok6_key).unwrap();
    assert!(token.is_none());
    let token: Option<Token> = json_may_load(&info_store, &tok7_key).unwrap();
    assert!(token.is_none());
    let token: Option<Token> = json_may_load(&info_store, &tok8_key).unwrap();
    assert!(token.is_none());
    // confirm NFT3 metadata has been deleted from storage
    let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
    let priv_meta: Option<Metadata> = may_load(&priv_store, &tok3_key).unwrap();
    assert!(priv_meta.is_none());
    let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
    let pub_meta: Option<Metadata> = may_load(&pub_store, &tok3_key).unwrap();
    assert!(pub_meta.is_none());
    // confirm NFT2 is intact
    let token: Token = json_load(&info_store, &tok2_key).unwrap();
    assert_eq!(token.permissions.len(), 1);
    let charlie_tok_perm = token
        .permissions
        .iter()
        .find(|p| p.address == charlie_raw)
        .unwrap();
    assert_eq!(
        charlie_tok_perm.expirations[view_meta_idx],
        Some(Expiration::Never)
    );
    assert_eq!(charlie_tok_perm.expirations[transfer_idx], None);
    assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
    assert_eq!(token.owner, alice_raw);
    assert!(!token.unwrapped);
    // confirm owner lists are correct
    let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
    // alice only owns NFT2
    let alice_owns: HashSet<u32> = load(&owned_store, alice_key).unwrap();
    assert_eq!(alice_owns.len(), 1);
    assert!(alice_owns.contains(&1u32));
    // bob owns NFT4 and NFT5
    let bob_owns: HashSet<u32> = load(&owned_store, bob_key).unwrap();
    assert_eq!(bob_owns.len(), 2);
    assert!(bob_owns.contains(&3u32));
    assert!(bob_owns.contains(&4u32));
    // charlie does not own any
    let charlie_owns: Option<HashSet<u32>> = may_load(&owned_store, charlie_key).unwrap();
    assert!(charlie_owns.is_none());
    // confirm AuthLists are correct
    let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
    // alice gave charlie view metadata permission on NFT2
    let alice_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
    assert_eq!(alice_list.len(), 1);
    let charlie_auth = alice_list
        .iter()
        .find(|a| a.address == charlie_raw)
        .unwrap();
    assert_eq!(charlie_auth.tokens[view_meta_idx].len(), 1);
    assert!(charlie_auth.tokens[view_meta_idx].contains(&1u32));
    assert!(charlie_auth.tokens[transfer_idx].is_empty());
    assert!(charlie_auth.tokens[view_owner_idx].is_empty());
    // bob gave charlie view owner and view metadata permission on NFT5
    let bob_list: Vec<AuthList> = load(&auth_store, bob_key).unwrap();
    assert_eq!(bob_list.len(), 2);
    let charlie_auth = bob_list.iter().find(|a| a.address == charlie_raw).unwrap();
    assert_eq!(charlie_auth.tokens[view_meta_idx].len(), 1);
    assert!(charlie_auth.tokens[view_meta_idx].contains(&4u32));
    assert!(charlie_auth.tokens[transfer_idx].is_empty());
    assert_eq!(charlie_auth.tokens[view_owner_idx].len(), 1);
    assert!(charlie_auth.tokens[view_owner_idx].contains(&4u32));
    // bob gave alice view owner permission on NFT4 and NFT5
    // and transfer permission on NFT5
    let alice_auth = bob_list.iter().find(|a| a.address == alice_raw).unwrap();
    assert_eq!(alice_auth.tokens[transfer_idx].len(), 1);
    assert!(alice_auth.tokens[transfer_idx].contains(&4u32));
    assert!(alice_auth.tokens[view_meta_idx].is_empty());
    assert_eq!(alice_auth.tokens[view_owner_idx].len(), 2);
    assert!(alice_auth.tokens[view_owner_idx].contains(&3u32));
    assert!(alice_auth.tokens[view_owner_idx].contains(&4u32));
    // charlie has no tokens so should not have any AuthLists
    let charlie_list: Option<Vec<AuthList>> = may_load(&auth_store, charlie_key).unwrap();
    assert!(charlie_list.is_none());
    // confirm one of the txs
    let txs = get_txs(&deps.api, &deps.storage, &bob_raw, 0, 3).unwrap();
    assert_eq!(txs.len(), 3);
    assert_eq!(txs[0].token_id, "NFT8".to_string());
    assert_eq!(
        txs[0].action,
        TxAction::Burn {
            owner: HumanAddr("charlie".to_string()),
            burner: Some(HumanAddr("bob".to_string())),
        }
    );
    assert_eq!(txs[0].memo, Some("Phew!".to_string()));
    assert_eq!(txs[1].memo, Some("Phew!".to_string()));
    assert_eq!(txs[2].memo, Some("Phew!".to_string()));
    let tx2 = get_txs(&deps.api, &deps.storage, &charlie_raw, 0, 1).unwrap();
    assert_eq!(txs[0], tx2[0]);
}

fn grant_all(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>, granter: &str, grantee: &str) {
    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr(grantee.to_string()),
        token_id: None,
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::All),
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env(granter, &[]), handle_msg);
    assert!(result.is_ok());
}

fn mint_nft1_alice_grant_bob_charlie(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT1".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: Some(AccessLevel::ApproveToken),
        expires: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("charlie".to_string()),
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: None,
        transfer: Some(AccessLevel::ApproveToken),
        expires: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(handle_result.is_ok());
}

fn mint_nft2_alice_grant_charlie(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT2".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("charlie".to_string()),
        token_id: Some("NFT2".to_string()),
        view_owner: None,
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: None,
        expires: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(handle_result.is_ok());
}

fn mint_nft3_alice_grant_bob(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT3".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: Some(Metadata {
            name: Some("MyNFT3".to_string()),
            description: Some("privmetadata3".to_string()),
            image: Some("privuri3".to_string()),
        }),
        public_metadata: Some(Metadata {
            name: Some("MyNFT3".to_string()),
            description: Some("pubmetadata3".to_string()),
            image: Some("puburi3".to_string()),
        }),
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: Some("NFT3".to_string()),
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::ApproveToken),
        expires: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(handle_result.is_ok());
}

fn mint_nft4_bob_grant_alice(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT4".to_string()),
        owner: Some(HumanAddr("bob".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("alice".to_string()),
        token_id: Some("NFT4".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: None,
        transfer: None,
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(result.is_ok());
}

fn mint_nft5_bob_grant_alice_charlie(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT5".to_string()),
        owner: Some(HumanAddr("bob".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("alice".to_string()),
        token_id: Some("NFT5".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: None,
        transfer: Some(AccessLevel::ApproveToken),
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("charlie".to_string()),
        token_id: Some("NFT5".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: None,
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(result.is_ok());
}

fn mint_nft6_bob_grant_alice(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT6".to_string()),
        owner: Some(HumanAddr("bob".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("alice".to_string()),
        token_id: Some("NFT6".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: None,
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(result.is_ok());
}

fn mint_nft7_charlie_grant_alice(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT7".to_string()),
        owner: Some(HumanAddr("charlie".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("alice".to_string()),
        token_id: Some("NFT7".to_string()),
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::ApproveToken),
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(result.is_ok());
}

fn mint_nft8_charlie(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT8".to_string()),
        owner: Some(HumanAddr("charlie".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(handle_result.is_ok());
}

