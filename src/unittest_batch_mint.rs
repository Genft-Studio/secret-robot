#[cfg(test)]
mod tests {
    use crate::msg::{HandleMsg, ContractStatus, Mint, HandleAnswer, TxAction};
    use crate::contract::{handle};
    use cosmwasm_std::testing::mock_env;
    use cosmwasm_std::{HumanAddr, from_binary, Api};
    use crate::token::{Metadata, Token};
    use std::collections::HashSet;
    use crate::state::{load, TOKENS_KEY, PREFIX_MAP_TO_INDEX, PREFIX_MAP_TO_ID, PREFIX_INFOS, json_load, PREFIX_PUB_META, may_load, PREFIX_PRIV_META, PREFIX_OWNED, get_txs};
    use cosmwasm_storage::ReadonlyPrefixedStorage;
    use crate::unittest_helpers::{init_helper_verified, extract_error_msg, set_contract_status};

    // test batch mint when status prevents it
    #[test]
    fn test_batch_mint_when_suspended() {
        let mut deps = init_helper_verified();

        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        let mints = vec![
            Mint {
                token_id: None,
                owner: None,
                public_metadata: None,
                private_metadata: None,
                memo: None,
            },
        ];

        let handle_msg = HandleMsg::BatchMintNft {
            mints: mints.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        set_contract_status(&mut deps, ContractStatus::Normal);
    }

    #[test]
    fn test_batch_mint_duplicate_id() {
        let mut deps = init_helper_verified();

        let mints = vec![
            Mint {
                token_id: Some("Duplicated".to_string()),
                owner: None,
                public_metadata: None,
                private_metadata: None,
                memo: None,
            },
        ];

        // Mint the original token
        let handle_msg = HandleMsg::BatchMintNft {
            mints: mints.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(handle_result.is_ok());

        // Mint the duplicate token
        let handle_msg = HandleMsg::BatchMintNft {
            mints: mints.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID Duplicated is already in use"));
    }

    // test batch mint by non-minter
    #[test]
    fn test_batch_mint_by_non_minter() {
        let mut deps = init_helper_verified();

        let handle_msg = HandleMsg::BatchMintNft {
            mints: vec![
                Mint {
                    token_id: Some("ALICE-NFT".to_string()),
                    owner: None,
                    public_metadata: None,
                    private_metadata: None,
                    memo: None,
                },
            ],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());
    }

    // test batch mint
    #[test]
    fn test_batch_mint() {
        let mut deps = init_helper_verified();

        let admin = HumanAddr("admin".to_string());
        let admin_raw = deps.api.canonical_address(&admin).unwrap();
        let pub1 = Metadata {
            name: Some("NFT1".to_string()),
            description: Some("pub1".to_string()),
            image: Some("uri1".to_string()),
        };
        let priv2 = Metadata {
            name: Some("NFT2".to_string()),
            description: Some("priv2".to_string()),
            image: Some("uri2".to_string()),
        };
        let mints = vec![
            Mint {
                token_id: None,
                owner: Some(admin.clone()),
                public_metadata: Some(pub1.clone()),
                private_metadata: None,
                memo: None,
            },
            Mint {
                token_id: Some("NFT2".to_string()),
                owner: None,
                public_metadata: None,
                private_metadata: Some(priv2.clone()),
                memo: None,
            },
            Mint {
                token_id: Some("NFT3".to_string()),
                owner: Some(admin.clone()),
                public_metadata: None,
                private_metadata: None,
                memo: None,
            },
            Mint {
                token_id: None,
                owner: Some(admin.clone()),
                public_metadata: None,
                private_metadata: None,
                memo: Some("has id 3".to_string()),
            },
        ];

        // sanity check
        let handle_msg = HandleMsg::BatchMintNft {
            mints: mints.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let minted_vec = vec![
            "0".to_string(),
            "NFT2".to_string(),
            "NFT3".to_string(),
            "3".to_string(),
        ];
        let handle_answer: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        match handle_answer {
            HandleAnswer::BatchMintNft { token_ids } => {
                assert_eq!(token_ids, minted_vec);
            }
            _ => panic!("unexpected"),
        }

        // verify the tokens are in the id and index maps
        let tokens: HashSet<String> = load(&deps.storage, TOKENS_KEY).unwrap();
        assert_eq!(tokens.len(), 4);
        assert!(tokens.contains("0"));
        assert!(tokens.contains("NFT2"));
        assert!(tokens.contains("NFT3"));
        assert!(tokens.contains("3"));
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index1: u32 = load(&map2idx, "0".as_bytes()).unwrap();
        let token_key1 = index1.to_le_bytes();
        let index2: u32 = load(&map2idx, "NFT2".as_bytes()).unwrap();
        let token_key2 = index2.to_le_bytes();
        let index3: u32 = load(&map2idx, "NFT3".as_bytes()).unwrap();
        let token_key3 = index3.to_le_bytes();
        let index4: u32 = load(&map2idx, "3".as_bytes()).unwrap();
        let token_key4 = index4.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id1: String = load(&map2id, &token_key1).unwrap();
        assert_eq!("0".to_string(), id1);
        let id2: String = load(&map2id, &token_key2).unwrap();
        assert_eq!("NFT2".to_string(), id2);
        let id3: String = load(&map2id, &token_key3).unwrap();
        assert_eq!("NFT3".to_string(), id3);
        let id4: String = load(&map2id, &token_key4).unwrap();
        assert_eq!("3".to_string(), id4);

        // verify all the token info
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token1: Token = json_load(&info_store, &token_key1).unwrap();
        assert_eq!(token1.owner, admin_raw);
        assert_eq!(token1.permissions, Vec::new());
        assert!(token1.unwrapped);
        let token2: Token = json_load(&info_store, &token_key2).unwrap();
        assert_eq!(token2.owner, admin_raw);
        assert_eq!(token2.permissions, Vec::new());
        assert!(token2.unwrapped);

        // verify the token metadata
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta1: Metadata = load(&pub_store, &token_key1).unwrap();
        assert_eq!(pub_meta1, pub1);
        let pub_meta2: Option<Metadata> = may_load(&pub_store, &token_key2).unwrap();
        assert!(pub_meta2.is_none());
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta1: Option<Metadata> = may_load(&priv_store, &token_key1).unwrap();
        assert!(priv_meta1.is_none());
        let priv_meta2: Metadata = load(&priv_store, &token_key2).unwrap();
        assert_eq!(priv_meta2, priv2);

        // verify owner lists
        let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
        let owned: HashSet<u32> = load(&owned_store, admin_raw.as_slice()).unwrap();
        assert!(owned.contains(&0));
        assert!(owned.contains(&2));
        let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
        let owned: HashSet<u32> = load(&owned_store, admin_raw.as_slice()).unwrap();
        assert!(owned.contains(&1));
        assert!(owned.contains(&3));

        // verify mint tx was logged
        let txs = get_txs(&deps.api, &deps.storage, &admin_raw, 0, 4).unwrap();
        assert_eq!(txs.len(), 4);
        assert_eq!(txs[0].token_id, "3".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Mint {
                minter: admin.clone(),
                recipient: admin,
            }
        );
        assert_eq!(txs[0].memo, Some("has id 3".to_string()));
    }
}
