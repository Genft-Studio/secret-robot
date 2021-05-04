#[cfg(test)]
mod tests {
    use crate::unittest_helpers::{init_helper_with_config, set_contract_status, extract_error_msg};
    use crate::msg::{HandleMsg, ContractStatus, Transfer, Mint, AccessLevel, TxAction, QueryMsg, QueryAnswer, Tx};
    use cosmwasm_std::{HumanAddr, Api, from_binary};
    use crate::token::{Metadata, Token};
    use crate::contract::{handle, query};
    use cosmwasm_std::testing::mock_env;
    use crate::state::{PermissionType, PREFIX_INFOS, json_load, load, TOKENS_KEY, PREFIX_MAP_TO_INDEX, PREFIX_MAP_TO_ID, get_txs, PREFIX_OWNED, PREFIX_AUTHLIST, AuthList};
    use cosmwasm_storage::ReadonlyPrefixedStorage;
    use std::collections::HashSet;

    #[test]
    fn test_batch_transfer() {
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

        // test transfer when status prevents it
        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        let transfers = vec![Transfer {
            recipient: HumanAddr("bob".to_string()),
            token_ids: vec!["MyNFT".to_string()],
            memo: None,
        }];
        let handle_msg = HandleMsg::BatchTransferNft {
            transfers,
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
        let transfers = vec![Transfer {
            recipient: HumanAddr("bob".to_string()),
            token_ids: vec!["MyNFT".to_string()],
            memo: None,
        }];

        // test token not found when supply is public
        let handle_msg = HandleMsg::BatchTransferNft {
            transfers,
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

        // set up for batch transfer test
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

        let transfers = vec![
            Transfer {
                recipient: HumanAddr("charlie".to_string()),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
            Transfer {
                recipient: HumanAddr("alice".to_string()),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
            Transfer {
                recipient: HumanAddr("bob".to_string()),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
            Transfer {
                recipient: HumanAddr("david".to_string()),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
        ];

        // test transferring the same token among address the sender has ALL permission,
        // but then breaks when it gets to an address he does not have authority for
        let handle_msg = HandleMsg::BatchTransferNft {
            transfers,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("david", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You are not authorized to perform this action on token NFT1"));
        // confirm it didn't die until david tried to transfer itaway from bob
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, bob_raw);

        // set up for batch transfer test
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

        let transfers = vec![
            Transfer {
                recipient: HumanAddr("charlie".to_string()),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
            Transfer {
                recipient: HumanAddr("alice".to_string()),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
            Transfer {
                recipient: HumanAddr("bob".to_string()),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
        ];

        // test transferring the same token among address the sender has ALL permission
        // and verify the AuthLists are correct after all the transfers
        let handle_msg = HandleMsg::BatchTransferNft {
            transfers,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("david", &[]), handle_msg);
        assert!(result.is_ok());

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

        let transfers = vec![
            Transfer {
                recipient: HumanAddr("charlie".to_string()),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
            Transfer {
                recipient: HumanAddr("alice".to_string()),
                token_ids: vec!["NFT5".to_string()],
                memo: None,
            },
            Transfer {
                recipient: HumanAddr("bob".to_string()),
                token_ids: vec!["NFT3".to_string()],
                memo: None,
            },
        ];

        // test bobs trnsfer two of his tokens and one of alice's
        let handle_msg = HandleMsg::BatchTransferNft {
            transfers,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(result.is_ok());

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

        // set up for batch transfer test
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

        let handle_msg = HandleMsg::BatchTransferNft {
            transfers: vec![
                Transfer {
                    recipient: HumanAddr("charlie".to_string()),
                    token_ids: vec!["NFT2".to_string(), "NFT3".to_string(), "NFT4".to_string()],
                    memo: Some("test memo".to_string()),
                },
                Transfer {
                    recipient: HumanAddr("charlie".to_string()),
                    token_ids: vec!["NFT1".to_string(), "NFT5".to_string()],
                    memo: None,
                },
            ],
            padding: None,
        };
        let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetViewingKey {
            key: "ckey".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm charlie's tokens
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
                let expected = vec![
                    "NFT1".to_string(),
                    "NFT2".to_string(),
                    "NFT3".to_string(),
                    "NFT4".to_string(),
                    "NFT5".to_string(),
                    "NFT6".to_string(),
                ];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }
        let xfer4 = Tx {
            tx_id: 8,
            blockheight: 12345,
            token_id: "NFT4".to_string(),
            memo: Some("test memo".to_string()),
            action: TxAction::Transfer {
                from: HumanAddr("bob".to_string()),
                sender: None,
                recipient: HumanAddr("charlie".to_string()),
            },
        };
        let xfer1 = Tx {
            tx_id: 9,
            blockheight: 12345,
            token_id: "NFT1".to_string(),
            memo: None,
            action: TxAction::Transfer {
                from: HumanAddr("alice".to_string()),
                sender: Some(HumanAddr("bob".to_string())),
                recipient: HumanAddr("charlie".to_string()),
            },
        };
        let query_msg = QueryMsg::TransactionHistory {
            address: HumanAddr("charlie".to_string()),
            viewing_key: "ckey".to_string(),
            page: None,
            page_size: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { txs } => {
                assert_eq!(txs[1], xfer1);
                assert_eq!(txs[2], xfer4);
            }
            _ => panic!("unexpected"),
        }
        let query_msg = QueryMsg::TransactionHistory {
            address: HumanAddr("charlie".to_string()),
            viewing_key: "ckey".to_string(),
            page: None,
            page_size: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { txs } => {
                assert_eq!(txs[1], xfer1);
                assert_eq!(txs[2], xfer4);
            }
            _ => panic!("unexpected"),
        }
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

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
                assert!(tokens.is_empty());
            }
            _ => panic!("unexpected"),
        }
    }
}
