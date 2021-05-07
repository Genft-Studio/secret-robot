#[cfg(test)]
mod tests {
    use crate::unittest_helpers::{init_helper_with_config, extract_error_msg, set_contract_status};
    use crate::msg::{HandleMsg, ContractStatus, TxAction, HandleAnswer};
    use cosmwasm_std::{HumanAddr, Env, BlockInfo, MessageInfo, Api, from_binary};
    use crate::token::{Metadata, Token};
    use crate::contract::{handle};
    use cosmwasm_std::testing::{mock_env, MOCK_CONTRACT_ADDR};
    use crate::expiration::Expiration;
    use std::collections::HashSet;
    use crate::state::{load, TOKENS_KEY, PREFIX_MAP_TO_INDEX, may_load, PREFIX_MAP_TO_ID, PREFIX_INFOS, json_may_load, PREFIX_PRIV_META, PREFIX_PUB_META, get_txs, PREFIX_AUTHLIST, AuthList, PREFIX_OWNED, PermissionType, json_load};
    use cosmwasm_storage::ReadonlyPrefixedStorage;

    // test burn
    #[test]
    fn test_burn_by_owner() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let token_key = 0u32.to_le_bytes();
        let alice_raw = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let alice_key = alice_raw.as_slice();

        // Mint NFT3
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT3".to_string()),
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

        // sanity check: owner burns
        let handle_msg = HandleMsg::BurnNft {
            token_id: "MyNFT3".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());

        // confirm token was removed from the maps
        let tokens: HashSet<String> = load(&deps.storage, TOKENS_KEY).unwrap();
        assert!(tokens.is_empty());
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index: Option<u32> = may_load(&map2idx, "MyNFT3".as_bytes()).unwrap();
        assert!(index.is_none());
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id: Option<String> = may_load(&map2id, &02u32.to_le_bytes()).unwrap();
        assert!(id.is_none());
        // confirm token info was deleted from storage
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Option<Token> = json_may_load(&info_store, &token_key).unwrap();
        assert!(token.is_none());
        // confirm the metadata has been deleted from storage
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &token_key).unwrap();
        assert!(priv_meta.is_none());
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &token_key).unwrap();
        assert!(pub_meta.is_none());
        // confirm the tx was logged
        let txs = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(txs[0].token_id, "MyNFT3".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Burn {
                owner: HumanAddr("alice".to_string()),
                burner: None,
            }
        );
        assert!(txs[0].memo.is_none());
        // confirm david's AuthList was removed because the only token was burned
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());
        // confirm the token was removed form the owner's list
        let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
        let owned: Option<HashSet<u32>> = may_load(&owned_store, alice_key).unwrap();
        assert!(owned.is_none());
    }

    #[test]
    fn test_burn_by_address_with_token_permission() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let tok1_key = 0u32.to_le_bytes();
        let tok2_key = 1u32.to_le_bytes();
        let alice_raw = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let alice_key = alice_raw.as_slice();
        let charlie_raw = deps
            .api
            .canonical_address(&HumanAddr("charlie".to_string()))
            .unwrap();
        let david_raw = deps
            .api
            .canonical_address(&HumanAddr("david".to_string()))
            .unwrap();

        let transfer_idx = PermissionType::Transfer.to_usize();

        // sanity check: address with token permission burns it

        // mint NFT2
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            private_metadata: Some(Metadata {
                name: Some("MyNFT2".to_string()),
                description: Some("privmetadata2".to_string()),
                image: Some("privuri2".to_string()),
            }),
            public_metadata: Some(Metadata {
                name: Some("MyNFT2".to_string()),
                description: Some("pubmetadata2".to_string()),
                image: Some("puburi2".to_string()),
            }),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());

        // Mint NFT3
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT3".to_string()),
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

        // approve charlie
        let handle_msg = HandleMsg::Approve {
            spender: HumanAddr("charlie".to_string()),
            token_id: "MyNFT2".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());

        // approve david
        let handle_msg = HandleMsg::Approve {
            spender: HumanAddr("david".to_string()),
            token_id: "MyNFT3".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());

        // charlie burns NFT2
        let handle_msg = HandleMsg::BurnNft {
            token_id: "MyNFT2".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = handle(
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
        assert!(handle_result.is_ok());

        // confirm token was removed from the maps
        let tokens: HashSet<String> = load(&deps.storage, TOKENS_KEY).unwrap();
        assert!(!tokens.contains("MyNFT2"));
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index: Option<u32> = may_load(&map2idx, "MyNFT2".as_bytes()).unwrap();
        assert!(index.is_none());
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id: Option<String> = may_load(&map2id, &tok1_key).unwrap();
        assert!(id.is_none());
        // confirm token info was deleted from storage
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Option<Token> = json_may_load(&info_store, &tok1_key).unwrap();
        assert!(token.is_none());
        // confirm MyNFT3 is intact
        let token: Token = json_load(&info_store, &tok2_key).unwrap();
        let david_perm = token.permissions.iter().find(|p| p.address == david_raw);
        assert!(david_perm.is_some());
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Metadata = load(&priv_store, &tok2_key).unwrap();
        assert_eq!(priv_meta.name, Some("MyNFT3".to_string()));
        assert_eq!(priv_meta.description, Some("privmetadata3".to_string()));
        assert_eq!(priv_meta.image, Some("privuri3".to_string()));
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &tok2_key).unwrap();
        assert_eq!(pub_meta.name, Some("MyNFT3".to_string()));
        assert_eq!(pub_meta.description, Some("pubmetadata3".to_string()));
        assert_eq!(pub_meta.image, Some("puburi3".to_string()));
        // confirm the MyNFT2 metadata has been deleted from storage
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &tok1_key).unwrap();
        assert!(priv_meta.is_none());
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &tok1_key).unwrap();
        assert!(pub_meta.is_none());
        // confirm the tx was logged to both parties
        let txs = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(txs[0].token_id, "MyNFT2".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Burn {
                owner: HumanAddr("alice".to_string()),
                burner: Some(HumanAddr("charlie".to_string())),
            }
        );
        assert!(txs[0].memo.is_none());
        let tx2 = get_txs(&deps.api, &deps.storage, &charlie_raw, 0, 1).unwrap();
        assert_eq!(txs, tx2);
        // confirm charlie's AuthList was removed because his only approved token was burned
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw);
        assert!(charlie_auth.is_none());
        let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[transfer_idx].len(), 1);
        assert!(david_auth.tokens[transfer_idx].contains(&1u32));
        // confirm the token was removed form the owner's list
        let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
        let owned: HashSet<u32> = load(&owned_store, alice_key).unwrap();
        assert!(!owned.contains(&0u32));
        assert!(owned.contains(&1u32));
    }

    #[test]
    fn test_burn_address_with_account_permission() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, true);
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
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());

        // Grant bob permission to all of alices tokens
        let handle_msg = HandleMsg::ApproveAll {
            operator: HumanAddr("bob".to_string()),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());

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

        // sanity check: operator burns
        let handle_msg = HandleMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: Some("Burn, baby, burn!".to_string()),
            padding: None,
        };
        let handle_result = handle(
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

        let answer: HandleAnswer = from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        match answer {
            HandleAnswer::BurnNft { secret } => {
                assert_eq!(secret.description.unwrap(), "metadata");
                assert_eq!(secret.image.unwrap(), "uri");
                assert_eq!(secret.name.unwrap(), "MyNFT")
            },
            _ => panic!("NOPE"),
        };

        // confirm token was removed from the maps
        let tokens: HashSet<String> = load(&deps.storage, TOKENS_KEY).unwrap();
        assert!(!tokens.contains("MyNFT"));
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index: Option<u32> = may_load(&map2idx, "MyNFT".as_bytes()).unwrap();
        assert!(index.is_none());
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id: Option<String> = may_load(&map2id, &tok_key).unwrap();
        assert!(id.is_none());
        // confirm token info was deleted from storage
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Option<Token> = json_may_load(&info_store, &tok_key).unwrap();
        assert!(token.is_none());
        // confirm the metadata has been deleted from storage
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &tok_key).unwrap();
        assert!(priv_meta.is_none());
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &tok_key).unwrap();
        assert!(pub_meta.is_none());
        // confirm the tx was logged to both parties
        let txs = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Burn {
                owner: HumanAddr("alice".to_string()),
                burner: Some(HumanAddr("bob".to_string())),
            }
        );
        assert_eq!(txs[0].memo, Some("Burn, baby, burn!".to_string()));
        let tx2 = get_txs(&deps.api, &deps.storage, &bob_raw, 0, 1).unwrap();
        assert_eq!(txs, tx2);
        // confirm charlie's AuthList was removed because the only token was burned
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());
        // confirm the token was removed form the owner's list
        let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
        let owned: Option<HashSet<u32>> = may_load(&owned_store, alice_key).unwrap();
        assert!(owned.is_none());
    }

    #[test]
    fn test_burn_expired_all_approval_permission() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, true);
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
                description: None,
                image: Some("uri".to_string()),
            }),
            public_metadata: Some(Metadata {
                name: Some("MyPublicNFT".to_string()),
                description: Some("public metadata".to_string()),
                image: Some("public uri".to_string()),
            }),
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());

        // test expired ALL approval
        let handle_msg = HandleMsg::ApproveAll {
            operator: HumanAddr("bob".to_string()),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());

        let handle_msg = HandleMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: None,
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
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        match answer {
            HandleAnswer::BurnNft { secret } => {
                assert_eq!(secret.description.unwrap(), "public metadata");
                assert_eq!(secret.image.unwrap(), "uri");
                assert_eq!(secret.name.unwrap(), "MyNFT")
            },
            _ => panic!("NOPE"),
        };
    }

    #[test]
    fn test_burn_with_expired_approval() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            private_metadata: None,
            public_metadata: Some(Metadata {
                name: Some("MyNFT".to_string()),
                description: Some("metadata".to_string()),
                image: Some("uri".to_string()),
            }),
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());

        // test expired approval permission
        let handle_msg = HandleMsg::Approve {
            spender: HumanAddr("charlie".to_string()),
            token_id: "MyNFT".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());

        let handle_msg = HandleMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: None,
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
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        match answer {
            HandleAnswer::BurnNft { secret } => {
                assert_eq!(secret.description.unwrap(), "metadata");
                assert_eq!(secret.image.unwrap(), "uri");
                assert_eq!(secret.name.unwrap(), "MyNFT")
            },
            _ => panic!("NOPE"),
        };
    }

    #[test]
    fn test_burn_by_unauthorized_address() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            private_metadata: Some(Metadata {
                name: None,
                description: Some("privmetadata".to_string()),
                image: Some("privuri".to_string()),
            }),
            public_metadata: Some(Metadata {
                name: Some("MyNFT".to_string()),
                description: Some("pubmetadata".to_string()),
                image: Some("puburi".to_string()),
            }),
            memo: Some("Mint public with metadata!".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());

        // test unauthorized addres
        let handle_msg = HandleMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        match answer {
            HandleAnswer::BurnNft { secret } => {
                assert_eq!(secret.description.unwrap(), "privmetadata");
                assert_eq!(secret.image.unwrap(), "privuri");
                assert_eq!(secret.name.unwrap(), "MyNFT")
            },
            _ => panic!("NOPE"),
        };
    }

    #[test]
    fn test_burn_when_not_found_and_supply_is_private() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is private
        let handle_msg = HandleMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You are not authorized to perform this action on token MyNFT"));
    }

    #[test]
    fn test_burn_when_not_found_and_supply_is_public() {
        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: MyNFT not found"));
    }

    #[test]
    fn test_burn_when_disabled() {
        // enable_burn is ignored
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
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());

        let handle_msg = HandleMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());
    }

    // test burn when status prevents it
    #[test]
    fn test_burn_when_status_prevents_it() {
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
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());

        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        let handle_msg = HandleMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        set_contract_status(&mut deps, ContractStatus::Normal);
    }
}
