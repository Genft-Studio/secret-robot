#[cfg(test)]
mod tests {
    use crate::unittest_helpers::{init_helper_with_config, extract_error_msg, init_helper_default, set_contract_status};
    use crate::msg::{HandleMsg, ContractStatus};
    use crate::token::Metadata;
    use crate::contract::{handle};
    use cosmwasm_std::testing::mock_env;
    use cosmwasm_std::HumanAddr;
    use cosmwasm_storage::ReadonlyPrefixedStorage;
    use crate::state::{PREFIX_PUB_META, load, PREFIX_PRIV_META, may_load};

    #[test]
    fn test_set_public_metadata() {
        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is public
        let handle_msg = HandleMsg::SetPublicMetadata {
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

        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is private
        let handle_msg = HandleMsg::SetPublicMetadata {
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

        // test setting metadata when status prevents it
        set_contract_status(&mut deps, ContractStatus::StopAll);

        let handle_msg = HandleMsg::SetPublicMetadata {
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

        set_contract_status(&mut deps, ContractStatus::Normal);

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

        // test not minter nor owner
        let handle_msg = HandleMsg::SetPublicMetadata {
            token_id: "MyNFT".to_string(),
            metadata: Metadata {
                name: Some("New Name".to_string()),
                description: Some("I changed the metadata".to_string()),
                image: Some("new uri".to_string()),
            },
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Not authorized to update metadata"));

        // test owner tries but not allowed to change metadata
        let handle_msg = HandleMsg::SetPublicMetadata {
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
        assert!(error.contains("Not authorized to update metadata"));

        // test minter tries, but not allowed
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

        let handle_msg = HandleMsg::SetPublicMetadata {
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
        assert!(error.contains("Not authorized to update metadata"));

        // sanity check: minter updates
        let (init_result, mut deps) = init_helper_default();
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

        let handle_msg = HandleMsg::SetPublicMetadata {
            token_id: "MyNFT".to_string(),
            metadata: Metadata {
                name: Some("New Name".to_string()),
                description: Some("I changed the metadata".to_string()),
                image: Some("new uri".to_string()),
            },
            padding: None,
        };
        let result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(result.is_ok());

        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &0u32.to_le_bytes()).unwrap();
        assert_eq!(pub_meta.name, Some("New Name".to_string()));
        assert_eq!(
            pub_meta.description,
            Some("I changed the metadata".to_string())
        );
        assert_eq!(pub_meta.image, Some("new uri".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &0u32.to_le_bytes()).unwrap();
        assert!(priv_meta.is_none());
    }
}
