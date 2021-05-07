#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use crate::msg::{HandleMsg, ContractStatus};
    use crate::token::{Metadata, Token};
    use crate::contract::handle;
    use cosmwasm_std::testing::mock_env;
    use cosmwasm_std::HumanAddr;
    use std::collections::HashSet;
    use crate::state::{load, TOKENS_KEY, PREFIX_MAP_TO_INDEX, PREFIX_MAP_TO_ID, PREFIX_INFOS, json_load, PREFIX_PRIV_META, PREFIX_PUB_META, may_load};
    use cosmwasm_storage::ReadonlyPrefixedStorage;

    #[test]
    fn test_set_private_metadata() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is private
        let handle_msg = HandleMsg::SetPrivateMetadata {
            token_id: "SNIP20".to_string(),
            metadata: Metadata {
                name: Some("New Name".to_string()),
                description: Some("I changed the metadata".to_string()),
                image: Some("new uri".to_string()),
            },
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Not authorized to update metadata of token SNIP20"));

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
            }),
            private_metadata: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // test trying to change sealed metadata before it has been unwrapped
        let (init_result, mut deps) =
            init_helper_with_config(true, false, true, true, true, false, false);
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
            public_metadata: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetPrivateMetadata {
            token_id: "MyNFT".to_string(),
            metadata: Metadata {
                name: Some("New Name".to_string()),
                description: Some("I changed the metadata".to_string()),
                image: Some("new uri".to_string()),
            },
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The private metadata of a sealed token can not be modified"));

        // test token does not exist when supply is public
        let handle_msg = HandleMsg::SetPrivateMetadata {
            token_id: "SNIP20".to_string(),
            metadata: Metadata {
                name: Some("New Name".to_string()),
                description: Some("I changed the metadata".to_string()),
                image: Some("new uri".to_string()),
            },
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: SNIP20 not found"));

        // sanity check, minter changing metadata after owner unwrapped
        let handle_msg = HandleMsg::Reveal {
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let tokens: HashSet<String> = load(&deps.storage, TOKENS_KEY).unwrap();
        assert!(tokens.contains("MyNFT"));
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &token_key).unwrap();
        assert!(token.unwrapped);
        let handle_msg = HandleMsg::SetPrivateMetadata {
            token_id: "MyNFT".to_string(),
            metadata: Metadata {
                name: Some("New Name".to_string()),
                description: Some("Minter changed the metadata".to_string()),
                image: Some("new uri".to_string()),
            },
            padding: None,
        };
        let result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(result.is_ok());

        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Metadata = load(&priv_store, &token_key).unwrap();
        assert_eq!(priv_meta.name, Some("New Name".to_string()));
        assert_eq!(
            priv_meta.description,
            Some("Minter changed the metadata".to_string())
        );
        assert_eq!(priv_meta.image, Some("new uri".to_string()));
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &token_key).unwrap();
        assert!(pub_meta.is_none());

        set_contract_status(&mut deps, ContractStatus::StopAll);

        let handle_msg = HandleMsg::SetPrivateMetadata {
            token_id: "MyNFT".to_string(),
            metadata: Metadata {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
            },
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        // test owner trying when not authorized
        let handle_msg = HandleMsg::SetPrivateMetadata {
            token_id: "MyNFT".to_string(),
            metadata: Metadata {
                name: Some("New Name".to_string()),
                description: Some("I changed the metadata".to_string()),
                image: Some("new uri".to_string()),
            },
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Not authorized to update metadata of token MyNFT"));

        // test authorized owner creates new metadata when it didn't exist before
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, true, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
            }),
            private_metadata: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetPrivateMetadata {
            token_id: "MyNFT".to_string(),
            metadata: Metadata {
                name: Some("New Name".to_string()),
                description: Some("Owner changed the metadata".to_string()),
                image: Some("new uri".to_string()),
            },
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Metadata = load(&priv_store, &token_key).unwrap();
        assert_eq!(priv_meta.name, Some("New Name".to_string()));
        assert_eq!(
            priv_meta.description,
            Some("Owner changed the metadata".to_string())
        );
        assert_eq!(priv_meta.image, Some("new uri".to_string()));
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &token_key).unwrap();
        assert_eq!(pub_meta.name, Some("MyNFT".to_string()));
        assert_eq!(pub_meta.description, None);
        assert_eq!(pub_meta.image, Some("uri".to_string()));
    }
}
