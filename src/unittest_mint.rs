#[cfg(test)]
mod tests {
    use crate::unittest_helpers::{init_helper_verified, extract_error_msg, extract_log, set_contract_status};
    use crate::msg::{HandleMsg, ContractStatus, HandleAnswer, TxAction};
    use crate::contract::{handle};
    use cosmwasm_std::testing::mock_env;
    use cosmwasm_std::{HumanAddr, from_binary, Api};
    use crate::token::{Metadata, Token};
    use std::collections::HashSet;
    use crate::state::{load, TOKENS_KEY, PREFIX_MAP_TO_INDEX, PREFIX_MAP_TO_ID, PREFIX_INFOS, json_load, PREFIX_PUB_META, PREFIX_PRIV_META, may_load, PREFIX_OWNED, get_txs};
    use cosmwasm_storage::ReadonlyPrefixedStorage;

    // test minting when status prevents it
    #[test]
    fn test_mint_when_status_prevents() {
        let mut deps = init_helper_verified();

        // Disable minting
        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        // Mint an NFT
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some(HumanAddr("admin".to_string())),
            public_metadata: Some(Metadata {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // Re-enable minting
        set_contract_status(&mut deps, ContractStatus::Normal);

        // Mint an NFT
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some(HumanAddr("admin".to_string())),
            public_metadata: Some(Metadata {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(handle_result.is_ok());
    }

    // test minting for someone else
    #[test]
    fn test_mint_for_someone_else() {
        let mut deps = init_helper_verified();
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You can only mint tokens for yourself"));
    }

    // test minting existing token id
    #[test]
    fn test_mint_existing_token_id() {
        let mut deps = init_helper_verified();

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: None,
            public_metadata: None,
            private_metadata: None,
            memo: Some("First instance".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(handle_result.is_ok());

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: None,
            public_metadata: None,
            private_metadata: None,
            memo: Some("Instance with duplicate id".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID MyNFT is already in use"));
    }

    // test minting without specifying recipient or id
    #[test]
    fn test_mint_without_specifying_recipient_or_id() {
        let mut deps = init_helper_verified();

        let handle_msg = HandleMsg::MintNft {
            token_id: None,
            owner: None,
            public_metadata: Some(Metadata {
                name: Some("AdminNFT".to_string()),
                description: None,
                image: None,
            }),
            private_metadata: None,
            memo: Some("Admin wants his own".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let minted_str = "0".to_string();
        let handle_answer: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        match handle_answer {
            HandleAnswer::MintNft { token_id } => {
                assert_eq!(token_id, minted_str);
            }
            _ => panic!("unexpected"),
        }

        // verify token is in the token list
        let tokens: HashSet<String> = load(&deps.storage, TOKENS_KEY).unwrap();
        assert!(tokens.contains("0"));
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index: u32 = load(&map2idx, "0".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("0".to_string(), id);

        // verify token info
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &token_key).unwrap();
        let admin_raw = deps
            .api
            .canonical_address(&HumanAddr("admin".to_string()))
            .unwrap();
        assert_eq!(token.owner, admin_raw);
        assert_eq!(token.permissions, Vec::new());
        assert!(token.unwrapped);

        // verify metadata
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &token_key).unwrap();
        assert_eq!(pub_meta.name, Some("AdminNFT".to_string()));
        assert_eq!(pub_meta.description, None);
        assert_eq!(pub_meta.image, None);
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &token_key).unwrap();
        assert!(priv_meta.is_none());

        // verify token is in the owner list
        let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
        let owned: HashSet<u32> = load(&owned_store, admin_raw.as_slice()).unwrap();
        assert!(owned.contains(&0));

        // verify mint tx was logged
        let txs = get_txs(&deps.api, &deps.storage, &admin_raw, 0, 10).unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].token_id, "0".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Mint {
                minter: HumanAddr("admin".to_string()),
                recipient: HumanAddr("admin".to_string()),
            }
        );
        assert_eq!(txs[0].memo, Some("Admin wants his own".to_string()));
    }

    // test minting by non-minter (everyone allowed to mint)
    #[test]
    fn test_mint_by_non_minter() {
        let mut deps = init_helper_verified();
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("AlicesSecret".to_string()),
            owner: None,
            public_metadata: Some(Metadata {
                name: Some("AlicesSecret".to_string()),
                description: None,
                image: Some("uri".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());
    }

    // test minting
    #[test]
    fn test_mint() {
        let mut deps = init_helper_verified();

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some(HumanAddr("admin".to_string())),
            public_metadata: Some(Metadata {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
            }),
            private_metadata: Some(Metadata {
                name: Some("MyNFTpriv".to_string()),
                description: Some("Nifty".to_string()),
                image: Some("privuri".to_string()),
            }),
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let minted = extract_log(handle_result);
        assert!(minted.contains("MyNFT"));

        // verify the token is in the id and index maps
        let tokens: HashSet<String> = load(&deps.storage, TOKENS_KEY).unwrap();
        assert!(tokens.contains("MyNFT"));
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);

        // verify all the token info
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &token_key).unwrap();
        let admin_raw = deps
            .api
            .canonical_address(&HumanAddr("admin".to_string()))
            .unwrap();
        assert_eq!(token.owner, admin_raw);
        assert_eq!(token.permissions, Vec::new());
        assert!(token.unwrapped);

        // verify the token metadata
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &token_key).unwrap();
        assert_eq!(pub_meta.name, Some("MyNFT".to_string()));
        assert_eq!(pub_meta.description, None);
        assert_eq!(pub_meta.image, Some("uri".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Metadata = load(&priv_store, &token_key).unwrap();
        assert_eq!(priv_meta.name, Some("MyNFTpriv".to_string()));
        assert_eq!(priv_meta.description, Some("Nifty".to_string()));
        assert_eq!(priv_meta.image, Some("privuri".to_string()));

        // verify token is in owner list
        let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
        let owned: HashSet<u32> = load(&owned_store, admin_raw.as_slice()).unwrap();
        assert!(owned.contains(&0));

        // verify mint tx was logged
        let txs = get_txs(&deps.api, &deps.storage, &admin_raw, 0, 1).unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Mint {
                minter: HumanAddr("admin".to_string()),
                recipient: HumanAddr("admin".to_string()),
            }
        );
        assert_eq!(txs[0].memo, Some("Mint it baby!".to_string()));
        let tx2 = get_txs(&deps.api, &deps.storage, &admin_raw, 0, 1).unwrap();
        assert_eq!(txs, tx2);
    }
}
