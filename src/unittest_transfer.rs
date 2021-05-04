#[cfg(test)]
mod tests {
    use crate::unittest_helpers::{init_helper_with_config, set_contract_status, extract_error_msg};
    use crate::msg::{HandleMsg, ContractStatus, AccessLevel, TxAction};
    use cosmwasm_std::{HumanAddr, Env, BlockInfo, MessageInfo, Api};
    use crate::token::{Metadata, Token};
    use crate::contract::handle;
    use cosmwasm_std::testing::{mock_env, MOCK_CONTRACT_ADDR};
    use crate::expiration::Expiration;
    use crate::state::{PermissionType, load, TOKENS_KEY, PREFIX_MAP_TO_INDEX, PREFIX_MAP_TO_ID, PREFIX_INFOS, json_load, get_txs, AuthList, PREFIX_PRIV_META, PREFIX_PUB_META, PREFIX_OWNED, may_load, PREFIX_AUTHLIST};
    use std::collections::HashSet;
    use cosmwasm_storage::ReadonlyPrefixedStorage;

    #[test]
    fn test_transfer() {
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

        let handle_msg = HandleMsg::TransferNft {
            recipient: HumanAddr("bob".to_string()),
            token_id: "MyNFT".to_string(),
            memo: None,
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

        // test token not found when supply is public
        let handle_msg = HandleMsg::TransferNft {
            recipient: HumanAddr("bob".to_string()),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: MyNFT not found"));

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is private
        let handle_msg = HandleMsg::TransferNft {
            recipient: HumanAddr("bob".to_string()),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You are not authorized to perform this action on token MyNFT"));

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            private_metadata: Some(Metadata {
                name: Some("MyNFT".to_string()),
                description: Some("privmetadata".to_string()),
                image: Some("privuri".to_string()),
            }),
            public_metadata: Some(Metadata {
                name: Some("MyNFT".to_string()),
                description: Some("pubmetadata".to_string()),
                image: Some("puburi".to_string()),
            }),
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // test unauthorized sender (but we'll give him view owner access)
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("MyNFT".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::TransferNft {
            recipient: HumanAddr("bob".to_string()),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You are not authorized to perform this action on token MyNFT"));

        // test expired token approval
        let handle_msg = HandleMsg::Approve {
            spender: HumanAddr("charlie".to_string()),
            token_id: "MyNFT".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::TransferNft {
            recipient: HumanAddr("bob".to_string()),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 100,
                    time: 100,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("charlie".to_string()),
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
        assert!(error.contains("Access to token MyNFT has expired"));

        // test expired ALL approval
        let handle_msg = HandleMsg::ApproveAll {
            operator: HumanAddr("bob".to_string()),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::TransferNft {
            recipient: HumanAddr("charlie".to_string()),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = handle(
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
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Access to all tokens of alice has expired"));

        let tok_key = 0u32.to_le_bytes();
        let alice_raw = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let alice_key = alice_raw.as_slice();
        let bob_raw = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let charlie_raw = deps
            .api
            .canonical_address(&HumanAddr("charlie".to_string()))
            .unwrap();
        let charlie_key = charlie_raw.as_slice();
        let david_raw = deps
            .api
            .canonical_address(&HumanAddr("david".to_string()))
            .unwrap();
        let david_key = david_raw.as_slice();
        let transfer_idx = PermissionType::Transfer.to_usize();
        let view_owner_idx = PermissionType::ViewOwner.to_usize();
        let view_meta_idx = PermissionType::ViewMetadata.to_usize();

        // confirm that transfering to the same address that owns the token does not
        // erase the current permissions
        let handle_msg = HandleMsg::TransferNft {
            recipient: HumanAddr("alice".to_string()),
            token_id: "MyNFT".to_string(),
            memo: Some("Xfer it".to_string()),
            padding: None,
        };
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 1,
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

        // confirm token was not removed from the maps
        let tokens: HashSet<String> = load(&deps.storage, TOKENS_KEY).unwrap();
        assert!(tokens.contains("MyNFT"));
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        // confirm token info is the same
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert_eq!(token.permissions.len(), 2);
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(10))
        );
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[transfer_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[view_owner_idx],
            Some(Expiration::Never)
        );
        assert!(token.unwrapped);
        // confirm no transfer tx was logged (latest should be the mint tx)
        let txs = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(
            txs[0].action,
            TxAction::Mint {
                minter: HumanAddr("alice".to_string()),
                recipient: HumanAddr("alice".to_string()),
            }
        );
        // confirm the owner list is correct
        let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
        let alice_owns: HashSet<u32> = load(&owned_store, alice_key).unwrap();
        assert_eq!(alice_owns.len(), 1);
        assert!(alice_owns.contains(&0u32));
        // confirm charlie's and bob's AuthList were not changed
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let alice_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(alice_list.len(), 2);
        let charlie_auth = alice_list
            .iter()
            .find(|a| a.address == charlie_raw)
            .unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&0u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        let bob_auth = alice_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[view_owner_idx].len(), 1);
        assert!(bob_auth.tokens[view_owner_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[transfer_idx].is_empty());

        // sanity check: operator transfers
        let handle_msg = HandleMsg::TransferNft {
            recipient: HumanAddr("david".to_string()),
            token_id: "MyNFT".to_string(),
            memo: Some("Xfer it".to_string()),
            padding: None,
        };
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 1,
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

        // confirm token was not removed from the maps
        let tokens: HashSet<String> = load(&deps.storage, TOKENS_KEY).unwrap();
        assert!(tokens.contains("MyNFT"));
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        // confirm token belongs to david now and permissions have been cleared
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, david_raw);
        assert!(token.permissions.is_empty());
        assert!(token.unwrapped);
        // confirm the metadata is intact
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
        assert_eq!(priv_meta.name, Some("MyNFT".to_string()));
        assert_eq!(priv_meta.description, Some("privmetadata".to_string()));
        assert_eq!(priv_meta.image, Some("privuri".to_string()));
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &tok_key).unwrap();
        assert_eq!(pub_meta.name, Some("MyNFT".to_string()));
        assert_eq!(pub_meta.description, Some("pubmetadata".to_string()));
        assert_eq!(pub_meta.image, Some("puburi".to_string()));
        // confirm the tx was logged to all involved parties
        let txs = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Transfer {
                from: HumanAddr("alice".to_string()),
                sender: Some(HumanAddr("bob".to_string())),
                recipient: HumanAddr("david".to_string()),
            }
        );
        assert_eq!(txs[0].memo, Some("Xfer it".to_string()));
        let tx2 = get_txs(&deps.api, &deps.storage, &bob_raw, 0, 1).unwrap();
        let tx3 = get_txs(&deps.api, &deps.storage, &david_raw, 0, 1).unwrap();
        assert_eq!(txs, tx2);
        assert_eq!(tx2, tx3);
        // confirm both owner lists are correct
        let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
        let alice_owns: Option<HashSet<u32>> = may_load(&owned_store, alice_key).unwrap();
        assert!(alice_owns.is_none());
        let david_owns: HashSet<u32> = load(&owned_store, david_key).unwrap();
        assert_eq!(david_owns.len(), 1);
        assert!(david_owns.contains(&0u32));
        // confirm charlie's and bob's AuthList were removed because the only token was xferred
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());
        // confirm david did not inherit any AuthLists from the xfer
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, david_key).unwrap();
        assert!(auth_list.is_none());

        // sanity check: address with token permission xfers it to itself
        let handle_msg = HandleMsg::Approve {
            spender: HumanAddr("charlie".to_string()),
            token_id: "MyNFT".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("david", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::TransferNft {
            recipient: HumanAddr("charlie".to_string()),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 1,
                    time: 100,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("charlie".to_string()),
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

        // confirm token was not removed from the list
        let tokens: HashSet<String> = load(&deps.storage, TOKENS_KEY).unwrap();
        assert!(tokens.contains("MyNFT"));
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        // confirm token belongs to charlie now and permissions have been cleared
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, charlie_raw);
        assert!(token.permissions.is_empty());
        assert!(token.unwrapped);
        // confirm the metadata is intact
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
        assert_eq!(priv_meta.name, Some("MyNFT".to_string()));
        assert_eq!(priv_meta.description, Some("privmetadata".to_string()));
        assert_eq!(priv_meta.image, Some("privuri".to_string()));
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &tok_key).unwrap();
        assert_eq!(pub_meta.name, Some("MyNFT".to_string()));
        assert_eq!(pub_meta.description, Some("pubmetadata".to_string()));
        assert_eq!(pub_meta.image, Some("puburi".to_string()));
        // confirm the tx was logged to all involved parties
        let txs = get_txs(&deps.api, &deps.storage, &charlie_raw, 0, 10).unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Transfer {
                from: HumanAddr("david".to_string()),
                sender: Some(HumanAddr("charlie".to_string())),
                recipient: HumanAddr("charlie".to_string()),
            }
        );
        assert_eq!(txs[0].memo, None);
        let tx2 = get_txs(&deps.api, &deps.storage, &david_raw, 0, 1).unwrap();
        assert_eq!(txs, tx2);
        // confirm both owner lists are correct
        let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
        let david_owns: Option<HashSet<u32>> = may_load(&owned_store, david_key).unwrap();
        assert!(david_owns.is_none());
        let charlie_owns: HashSet<u32> = load(&owned_store, charlie_key).unwrap();
        assert_eq!(charlie_owns.len(), 1);
        assert!(charlie_owns.contains(&0u32));
        // confirm charlie's AuthList was removed because the only token was xferred
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, david_key).unwrap();
        assert!(auth_list.is_none());
        // confirm charlie did not inherit any AuthLists from the xfer
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, charlie_key).unwrap();
        assert!(auth_list.is_none());

        // sanity check: owner xfers
        let handle_msg = HandleMsg::TransferNft {
            recipient: HumanAddr("alice".to_string()),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm token was not removed from the maps
        let tokens: HashSet<String> = load(&deps.storage, TOKENS_KEY).unwrap();
        assert!(tokens.contains("MyNFT"));
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        // confirm token belongs to alice now and permissions have been cleared
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.permissions.is_empty());
        assert!(token.unwrapped);
        // confirm the tx was logged to all involved parties
        let txs = get_txs(&deps.api, &deps.storage, &charlie_raw, 0, 1).unwrap();
        assert_eq!(txs[0].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Transfer {
                from: HumanAddr("charlie".to_string()),
                sender: None,
                recipient: HumanAddr("alice".to_string()),
            }
        );
        assert_eq!(txs[0].memo, None);
        let tx2 = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(txs, tx2);
        // confirm both owner lists are correct
        let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
        let charlie_owns: Option<HashSet<u32>> = may_load(&owned_store, charlie_key).unwrap();
        assert!(charlie_owns.is_none());
        let alice_owns: HashSet<u32> = load(&owned_store, alice_key).unwrap();
        assert_eq!(alice_owns.len(), 1);
        assert!(alice_owns.contains(&0u32));
        // confirm charlie's AuthList was removed because the only token was xferred
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());
        // confirm charlie did not inherit any AuthLists from the xfer
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, charlie_key).unwrap();
        assert!(auth_list.is_none());
    }
}
