use crate::unittest_helpers::{init_helper_with_config, set_contract_status, extract_error_msg};
use crate::msg::{HandleMsg, ContractStatus, AccessLevel, TxAction, Mint, QueryMsg, QueryAnswer, Send, Tx};
use cosmwasm_std::{HumanAddr, Api, to_binary, CosmosMsg, WasmMsg, Binary, from_binary};
use crate::token::{Metadata, Token};
use crate::contract::{handle, query};
use cosmwasm_std::testing::mock_env;
use crate::state::{PermissionType, load, TOKENS_KEY, PREFIX_MAP_TO_INDEX, PREFIX_MAP_TO_ID, PREFIX_INFOS, json_load, get_txs, PREFIX_OWNED, PREFIX_AUTHLIST, AuthList};
use crate::receiver::Snip721ReceiveMsg;
use secret_toolkit::utils::space_pad;
use std::collections::HashSet;
use cosmwasm_storage::ReadonlyPrefixedStorage;

#[test]
fn test_batch_send() {
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
            name: Some("MyNFT".to_string()),
            description: Some("metadata".to_string()),
            image: Some("uri".to_string()),
        }),
        public_metadata: None,
        memo: Some("Mint it baby!".to_string()),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    // test send when status prevents it
    set_contract_status(&mut deps, ContractStatus::StopTransactions);

    let sends = vec![Send {
        contract: HumanAddr("bob".to_string()),
        token_ids: vec!["MyNFT".to_string()],
        msg: None,
        memo: None,
    }];
    let handle_msg = HandleMsg::BatchSendNft {
        sends,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("The contract admin has temporarily disabled this action"));

    set_contract_status(&mut deps, ContractStatus::Normal);

    let (init_result, mut deps) =
        init_helper_with_config(true, false, false, false, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );
    let sends = vec![Send {
        contract: HumanAddr("bob".to_string()),
        token_ids: vec!["MyNFT".to_string()],
        msg: None,
        memo: None,
    }];

    // test token not found when supply is public
    let handle_msg = HandleMsg::BatchSendNft {
        sends,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    let error = extract_error_msg(handle_result);
    assert!(error.contains("Token ID: MyNFT not found"));

    let tok_key = 0u32.to_le_bytes();
    let tok5_key = 4u32.to_le_bytes();
    let tok3_key = 2u32.to_le_bytes();
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
    let david_raw = deps
        .api
        .canonical_address(&HumanAddr("david".to_string()))
        .unwrap();
    let transfer_idx = PermissionType::Transfer.to_usize();
    let view_owner_idx = PermissionType::ViewOwner.to_usize();
    let view_meta_idx = PermissionType::ViewMetadata.to_usize();

    // set up for batch send test
    let (init_result, mut deps) =
        init_helper_with_config(false, false, false, false, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT1".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT2".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT3".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT4".to_string()),
        owner: Some(HumanAddr("bob".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT5".to_string()),
        owner: Some(HumanAddr("bob".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT6".to_string()),
        owner: Some(HumanAddr("charlie".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: Some(AccessLevel::ApproveToken),
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("charlie".to_string()),
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: None,
        transfer: None,
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: Some("NFT2".to_string()),
        view_owner: None,
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: None,
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: Some("NFT3".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: Some(AccessLevel::ApproveToken),
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("david".to_string()),
        token_id: Some("NFT3".to_string()),
        view_owner: None,
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: None,
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("alice".to_string()),
        token_id: Some("NFT4".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: Some(AccessLevel::ApproveToken),
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("alice".to_string()),
        token_id: Some("NFT5".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: None,
        transfer: None,
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: Some("NFT6".to_string()),
        view_owner: None,
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: None,
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("david".to_string()),
        token_id: None,
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::All),
        expires: None,
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
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: None,
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::All),
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::RegisterReceiveNft {
        code_hash: "bob code hash".to_string(),
        also_implements_batch_receive_nft: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::RegisterReceiveNft {
        code_hash: "charlie code hash".to_string(),
        also_implements_batch_receive_nft: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(result.is_ok());

    // msg to go with ReceiveNft
    let send_msg = Some(
        to_binary(&HandleMsg::RevokeAll {
            operator: HumanAddr("zoe".to_string()),
            padding: None,
        })
            .unwrap(),
    );
    let sends = vec![
        Send {
            contract: HumanAddr("charlie".to_string()),
            token_ids: vec!["NFT1".to_string()],
            msg: send_msg.clone(),
            memo: None,
        },
        Send {
            contract: HumanAddr("alice".to_string()),
            token_ids: vec!["NFT1".to_string()],
            msg: send_msg.clone(),
            memo: None,
        },
        Send {
            contract: HumanAddr("bob".to_string()),
            token_ids: vec!["NFT1".to_string()],
            msg: send_msg.clone(),
            memo: None,
        },
    ];

    // test sending the same token among address the sender has ALL permission
    // and verify the AuthLists are correct after all the transfers
    let handle_msg = HandleMsg::BatchSendNft {
        sends,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("david", &[]), handle_msg);
    // confirm the receive nft msgs were created
    let handle_resp = handle_result.unwrap();
    let messages = handle_resp.messages;
    let mut msg_fr_al = to_binary(&Snip721ReceiveMsg::ReceiveNft {
        sender: HumanAddr("alice".to_string()),
        token_id: "NFT1".to_string(),
        msg: send_msg.clone(),
    })
        .unwrap();
    let msg_fr_al = space_pad(&mut msg_fr_al.0, 256usize);
    let msg_fr_al = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: HumanAddr("charlie".to_string()),
        callback_code_hash: "charlie code hash".to_string(),
        msg: Binary(msg_fr_al.to_vec()),
        send: vec![],
    });
    assert_eq!(messages[0], msg_fr_al);
    assert_eq!(messages.len(), 2);
    let mut msg_fr_al = to_binary(&Snip721ReceiveMsg::ReceiveNft {
        sender: HumanAddr("alice".to_string()),
        token_id: "NFT1".to_string(),
        msg: send_msg.clone(),
    })
        .unwrap();
    let msg_fr_al = space_pad(&mut msg_fr_al.0, 256usize);
    let msg_fr_al = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: HumanAddr("bob".to_string()),
        callback_code_hash: "bob code hash".to_string(),
        msg: Binary(msg_fr_al.to_vec()),
        send: vec![],
    });
    assert_eq!(messages[1], msg_fr_al);
    // confirm token was not removed from the maps
    let tokens: HashSet<String> = load(&deps.storage, TOKENS_KEY).unwrap();
    assert!(tokens.contains("NFT1"));
    let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
    let index: u32 = load(&map2idx, "NFT1".as_bytes()).unwrap();
    let token_key = index.to_le_bytes();
    let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
    let id: String = load(&map2id, &token_key).unwrap();
    assert_eq!("NFT1".to_string(), id);
    // confirm token has the correct owner and the permissions were cleared
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token: Token = json_load(&info_store, &tok_key).unwrap();
    assert_eq!(token.owner, bob_raw);
    assert!(token.permissions.is_empty());
    assert!(token.unwrapped);
    // confirm transfer txs were logged
    let txs = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 10).unwrap();
    assert_eq!(txs.len(), 6);
    assert_eq!(
        txs[2].action,
        TxAction::Transfer {
            from: HumanAddr("alice".to_string()),
            sender: Some(HumanAddr("david".to_string())),
            recipient: HumanAddr("charlie".to_string()),
        }
    );
    assert_eq!(
        txs[1].action,
        TxAction::Transfer {
            from: HumanAddr("charlie".to_string()),
            sender: Some(HumanAddr("david".to_string())),
            recipient: HumanAddr("alice".to_string()),
        }
    );
    assert_eq!(
        txs[0].action,
        TxAction::Transfer {
            from: HumanAddr("alice".to_string()),
            sender: Some(HumanAddr("david".to_string())),
            recipient: HumanAddr("bob".to_string()),
        }
    );
    // confirm the owner list is correct
    let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
    let alice_owns: HashSet<u32> = load(&owned_store, alice_key).unwrap();
    assert_eq!(alice_owns.len(), 2);
    assert!(!alice_owns.contains(&0u32));
    assert!(alice_owns.contains(&1u32));
    assert!(alice_owns.contains(&2u32));
    let bob_owns: HashSet<u32> = load(&owned_store, bob_key).unwrap();
    assert_eq!(bob_owns.len(), 3);
    assert!(bob_owns.contains(&0u32));
    assert!(bob_owns.contains(&3u32));
    assert!(bob_owns.contains(&4u32));
    let charlie_owns: HashSet<u32> = load(&owned_store, charlie_key).unwrap();
    assert_eq!(charlie_owns.len(), 1);
    assert!(charlie_owns.contains(&5u32));
    // confirm authLists were updated correctly
    let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
    let alice_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
    assert_eq!(alice_list.len(), 2);
    let david_auth = alice_list.iter().find(|a| a.address == david_raw).unwrap();
    assert_eq!(david_auth.tokens[view_meta_idx].len(), 1);
    assert!(david_auth.tokens[view_meta_idx].contains(&2u32));
    assert!(david_auth.tokens[transfer_idx].is_empty());
    assert!(david_auth.tokens[view_owner_idx].is_empty());
    let bob_auth = alice_list.iter().find(|a| a.address == bob_raw).unwrap();
    assert_eq!(bob_auth.tokens[view_owner_idx].len(), 1);
    assert!(bob_auth.tokens[view_owner_idx].contains(&2u32));
    assert_eq!(bob_auth.tokens[view_meta_idx].len(), 2);
    assert!(bob_auth.tokens[view_meta_idx].contains(&1u32));
    assert!(bob_auth.tokens[view_meta_idx].contains(&2u32));
    assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
    assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
    let bob_list: Vec<AuthList> = load(&auth_store, bob_key).unwrap();
    assert_eq!(bob_list.len(), 1);
    let alice_auth = bob_list.iter().find(|a| a.address == alice_raw).unwrap();
    assert_eq!(alice_auth.tokens[view_owner_idx].len(), 2);
    assert!(alice_auth.tokens[view_owner_idx].contains(&3u32));
    assert!(alice_auth.tokens[view_owner_idx].contains(&4u32));
    assert_eq!(alice_auth.tokens[view_meta_idx].len(), 1);
    assert!(alice_auth.tokens[view_meta_idx].contains(&3u32));
    assert_eq!(alice_auth.tokens[transfer_idx].len(), 1);
    assert!(alice_auth.tokens[transfer_idx].contains(&3u32));
    let charlie_list: Vec<AuthList> = load(&auth_store, charlie_key).unwrap();
    assert_eq!(charlie_list.len(), 1);
    let bob_auth = charlie_list.iter().find(|a| a.address == bob_raw).unwrap();
    assert!(bob_auth.tokens[view_owner_idx].is_empty());
    assert_eq!(bob_auth.tokens[view_meta_idx].len(), 1);
    assert!(bob_auth.tokens[view_meta_idx].contains(&5u32));
    assert!(bob_auth.tokens[transfer_idx].is_empty());

    let sends = vec![
        Send {
            contract: HumanAddr("charlie".to_string()),
            token_ids: vec!["NFT1".to_string()],
            msg: send_msg.clone(),
            memo: None,
        },
        Send {
            contract: HumanAddr("alice".to_string()),
            token_ids: vec!["NFT5".to_string()],
            msg: send_msg.clone(),
            memo: None,
        },
        Send {
            contract: HumanAddr("bob".to_string()),
            token_ids: vec!["NFT3".to_string()],
            msg: send_msg.clone(),
            memo: None,
        },
    ];

    // test bobs trnsfer two of his tokens and one of alice's
    let handle_msg = HandleMsg::BatchSendNft {
        sends,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    // confirm the receive nft msgs were created
    let handle_resp = handle_result.unwrap();
    let messages = handle_resp.messages;
    let mut msg_fr_b = to_binary(&Snip721ReceiveMsg::ReceiveNft {
        sender: HumanAddr("bob".to_string()),
        token_id: "NFT1".to_string(),
        msg: send_msg.clone(),
    })
        .unwrap();
    let msg_fr_b = space_pad(&mut msg_fr_b.0, 256usize);
    let msg_fr_b = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: HumanAddr("charlie".to_string()),
        callback_code_hash: "charlie code hash".to_string(),
        msg: Binary(msg_fr_b.to_vec()),
        send: vec![],
    });
    assert_eq!(messages[0], msg_fr_b);
    assert_eq!(messages.len(), 2);
    let mut msg_fr_al = to_binary(&Snip721ReceiveMsg::ReceiveNft {
        sender: HumanAddr("alice".to_string()),
        token_id: "NFT3".to_string(),
        msg: send_msg.clone(),
    })
        .unwrap();
    let msg_fr_al = space_pad(&mut msg_fr_al.0, 256usize);
    let msg_fr_al = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: HumanAddr("bob".to_string()),
        callback_code_hash: "bob code hash".to_string(),
        msg: Binary(msg_fr_al.to_vec()),
        send: vec![],
    });
    assert_eq!(messages[1], msg_fr_al);
    // confirm tokens have the correct owner and the permissions were cleared
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let token: Token = json_load(&info_store, &tok_key).unwrap();
    assert_eq!(token.owner, charlie_raw);
    assert!(token.permissions.is_empty());
    let token: Token = json_load(&info_store, &tok3_key).unwrap();
    assert_eq!(token.owner, bob_raw);
    assert!(token.permissions.is_empty());
    let token: Token = json_load(&info_store, &tok5_key).unwrap();
    assert_eq!(token.owner, alice_raw);
    assert!(token.permissions.is_empty());
    // confirm the owner list is correct
    let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
    let alice_owns: HashSet<u32> = load(&owned_store, alice_key).unwrap();
    assert_eq!(alice_owns.len(), 2);
    assert!(alice_owns.contains(&1u32));
    assert!(alice_owns.contains(&4u32));
    let bob_owns: HashSet<u32> = load(&owned_store, bob_key).unwrap();
    assert_eq!(bob_owns.len(), 2);
    assert!(bob_owns.contains(&2u32));
    assert!(bob_owns.contains(&3u32));
    let charlie_owns: HashSet<u32> = load(&owned_store, charlie_key).unwrap();
    assert_eq!(charlie_owns.len(), 2);
    assert!(charlie_owns.contains(&0u32));
    assert!(charlie_owns.contains(&5u32));
    // confirm authLists were updated correctly
    let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
    let alice_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
    assert_eq!(alice_list.len(), 1);
    let bob_auth = alice_list.iter().find(|a| a.address == bob_raw).unwrap();
    assert!(bob_auth.tokens[view_owner_idx].is_empty());
    assert_eq!(bob_auth.tokens[view_meta_idx].len(), 1);
    assert!(bob_auth.tokens[view_meta_idx].contains(&1u32));
    assert!(bob_auth.tokens[transfer_idx].is_empty());
    let bob_list: Vec<AuthList> = load(&auth_store, bob_key).unwrap();
    assert_eq!(bob_list.len(), 1);
    let alice_auth = bob_list.iter().find(|a| a.address == alice_raw).unwrap();
    assert_eq!(alice_auth.tokens[view_owner_idx].len(), 1);
    assert!(alice_auth.tokens[view_owner_idx].contains(&3u32));
    assert_eq!(alice_auth.tokens[view_meta_idx].len(), 1);
    assert!(alice_auth.tokens[view_meta_idx].contains(&3u32));
    assert_eq!(alice_auth.tokens[transfer_idx].len(), 1);
    assert!(alice_auth.tokens[transfer_idx].contains(&3u32));
    let charlie_list: Vec<AuthList> = load(&auth_store, charlie_key).unwrap();
    assert_eq!(charlie_list.len(), 1);
    let bob_auth = charlie_list.iter().find(|a| a.address == bob_raw).unwrap();
    assert!(bob_auth.tokens[view_owner_idx].is_empty());
    assert_eq!(bob_auth.tokens[view_meta_idx].len(), 1);
    assert!(bob_auth.tokens[view_meta_idx].contains(&5u32));
    assert!(bob_auth.tokens[transfer_idx].is_empty());

    // set up for batch send test
    let (init_result, mut deps) =
        init_helper_with_config(false, false, false, false, false, false, false);
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );
    let handle_msg = HandleMsg::BatchMintNft {
        mints: vec![
            Mint {
                token_id: Some("NFT1".to_string()),
                owner: Some(HumanAddr("alice".to_string())),
                private_metadata: None,
                public_metadata: None,
                memo: None,
            },
            Mint {
                token_id: Some("NFT2".to_string()),
                owner: Some(HumanAddr("alice".to_string())),
                private_metadata: None,
                public_metadata: None,
                memo: None,
            },
            Mint {
                token_id: Some("NFT3".to_string()),
                owner: Some(HumanAddr("alice".to_string())),
                private_metadata: None,
                public_metadata: None,
                memo: None,
            },
        ],
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::BatchMintNft {
        mints: vec![
            Mint {
                token_id: Some("NFT4".to_string()),
                owner: Some(HumanAddr("bob".to_string())),
                private_metadata: None,
                public_metadata: None,
                memo: None,
            },
            Mint {
                token_id: Some("NFT5".to_string()),
                owner: Some(HumanAddr("bob".to_string())),
                private_metadata: None,
                public_metadata: None,
                memo: None,
            },
        ],
        padding: None,
    };
    let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::BatchMintNft {
        mints: vec![
            Mint {
                token_id: Some("NFT6".to_string()),
                owner: Some(HumanAddr("charlie".to_string())),
                private_metadata: None,
                public_metadata: None,
                memo: None,
            },
        ],
        padding: None,
    };
    let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: None,
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::All),
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: None,
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::All),
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::RegisterReceiveNft {
        code_hash: "alice code hash".to_string(),
        also_implements_batch_receive_nft: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::RegisterReceiveNft {
        code_hash: "charlie code hash".to_string(),
        also_implements_batch_receive_nft: Some(true),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(result.is_ok());

    let send_msg = Some(
        to_binary(&HandleMsg::RevokeAll {
            operator: HumanAddr("zoe".to_string()),
            padding: None,
        })
            .unwrap(),
    );
    let handle_msg = HandleMsg::BatchSendNft {
        sends: vec![
            Send {
                contract: HumanAddr("charlie".to_string()),
                token_ids: vec!["NFT2".to_string(), "NFT3".to_string(), "NFT4".to_string()],
                msg: send_msg.clone(),
                memo: Some("test memo".to_string()),
            },
            Send {
                contract: HumanAddr("alice".to_string()),
                token_ids: vec!["NFT3".to_string(), "NFT4".to_string(), "NFT6".to_string()],
                msg: None,
                memo: None,
            },
        ],
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    let handle_resp = handle_result.unwrap();
    let messages = handle_resp.messages;
    let mut msg_fr_al = to_binary(&Snip721ReceiveMsg::BatchReceiveNft {
        sender: HumanAddr("bob".to_string()),
        from: HumanAddr("alice".to_string()),
        token_ids: vec!["NFT2".to_string(), "NFT3".to_string()],
        msg: send_msg.clone(),
    })
        .unwrap();
    let msg_fr_al = space_pad(&mut msg_fr_al.0, 256usize);
    let msg_fr_al = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: HumanAddr("charlie".to_string()),
        callback_code_hash: "charlie code hash".to_string(),
        msg: Binary(msg_fr_al.to_vec()),
        send: vec![],
    });
    let mut msf_fr_b = to_binary(&Snip721ReceiveMsg::BatchReceiveNft {
        sender: HumanAddr("bob".to_string()),
        from: HumanAddr("bob".to_string()),
        token_ids: vec!["NFT4".to_string()],
        msg: send_msg.clone(),
    })
        .unwrap();
    let msg_fr_b = space_pad(&mut msf_fr_b.0, 256usize);
    let msg_fr_b = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: HumanAddr("charlie".to_string()),
        callback_code_hash: "charlie code hash".to_string(),
        msg: Binary(msg_fr_b.to_vec()),
        send: vec![],
    });
    let mut msg_fr_c3 = to_binary(&Snip721ReceiveMsg::ReceiveNft {
        sender: HumanAddr("charlie".to_string()),
        token_id: "NFT3".to_string(),
        msg: None,
    })
        .unwrap();
    let msg_fr_c3 = space_pad(&mut msg_fr_c3.0, 256usize);
    let msg_fr_c3 = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: HumanAddr("alice".to_string()),
        callback_code_hash: "alice code hash".to_string(),
        msg: Binary(msg_fr_c3.to_vec()),
        send: vec![],
    });
    let mut msg_fr_c4 = to_binary(&Snip721ReceiveMsg::ReceiveNft {
        sender: HumanAddr("charlie".to_string()),
        token_id: "NFT4".to_string(),
        msg: None,
    })
        .unwrap();
    let msg_fr_c4 = space_pad(&mut msg_fr_c4.0, 256usize);
    let msg_fr_c4 = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: HumanAddr("alice".to_string()),
        callback_code_hash: "alice code hash".to_string(),
        msg: Binary(msg_fr_c4.to_vec()),
        send: vec![],
    });
    let mut msg_fr_c6 = to_binary(&Snip721ReceiveMsg::ReceiveNft {
        sender: HumanAddr("charlie".to_string()),
        token_id: "NFT6".to_string(),
        msg: None,
    })
        .unwrap();
    let msg_fr_c6 = space_pad(&mut msg_fr_c6.0, 256usize);
    let msg_fr_c6 = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: HumanAddr("alice".to_string()),
        callback_code_hash: "alice code hash".to_string(),
        msg: Binary(msg_fr_c6.to_vec()),
        send: vec![],
    });
    let expected_msgs = vec![msg_fr_al, msg_fr_b, msg_fr_c3, msg_fr_c4, msg_fr_c6];
    assert_eq!(messages, expected_msgs);
    let handle_msg = HandleMsg::SetViewingKey {
        key: "ckey".to_string(),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetViewingKey {
        key: "akey".to_string(),
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());

    // confirm alice's tokens
    let query_msg = QueryMsg::Tokens {
        owner: HumanAddr("alice".to_string()),
        viewer: None,
        viewing_key: Some("akey".to_string()),
        start_after: None,
        limit: Some(30),
    };
    let query_result = query(&deps, query_msg);
    let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
    match query_answer {
        QueryAnswer::TokenList { tokens } => {
            let expected = vec![
                "NFT1".to_string(),
                "NFT3".to_string(),
                "NFT4".to_string(),
                "NFT6".to_string(),
            ];
            assert_eq!(tokens, expected);
        }
        _ => panic!("unexpected"),
    }
    let xfer6 = Tx {
        tx_id: 11,
        blockheight: 12345,
        token_id: "NFT6".to_string(),
        memo: None,
        action: TxAction::Transfer {
            from: HumanAddr("charlie".to_string()),
            sender: Some(HumanAddr("bob".to_string())),
            recipient: HumanAddr("alice".to_string()),
        },
    };
    let xfer3 = Tx {
        tx_id: 7,
        blockheight: 12345,
        token_id: "NFT3".to_string(),
        memo: Some("test memo".to_string()),
        action: TxAction::Transfer {
            from: HumanAddr("alice".to_string()),
            sender: Some(HumanAddr("bob".to_string())),
            recipient: HumanAddr("charlie".to_string()),
        },
    };
    let query_msg = QueryMsg::TransactionHistory {
        address: HumanAddr("alice".to_string()),
        viewing_key: "akey".to_string(),
        page: None,
        page_size: None,
    };
    let query_result = query(&deps, query_msg);
    let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
    match query_answer {
        QueryAnswer::TransactionHistory { txs } => {
            assert_eq!(txs[3], xfer3);
            assert_eq!(txs[0], xfer6);
        }
        _ => panic!("unexpected"),
    }
    let query_msg = QueryMsg::Tokens {
        owner: HumanAddr("charlie".to_string()),
        viewer: None,
        viewing_key: Some("ckey".to_string()),
        start_after: None,
        limit: Some(30),
    };
    let query_result = query(&deps, query_msg);
    let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
    match query_answer {
        QueryAnswer::TokenList { tokens } => {
            let expected = vec!["NFT2".to_string()];
            assert_eq!(tokens, expected);
        }
        _ => panic!("unexpected"),
    }
}
