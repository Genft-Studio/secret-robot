#[cfg(test)]
mod tests {
    use crate::unittest_helpers::{init_helper_with_config, extract_error_msg};
    use cosmwasm_std::{HumanAddr, from_binary};
    use crate::msg::{HandleMsg, AccessLevel, QueryMsg, QueryAnswer, ViewerInfo};
    use crate::contract::{handle, query};
    use cosmwasm_std::testing::mock_env;
    use crate::token::Metadata;

    // test PrivateMetadata query
    #[test]
    fn test_private_metadata() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let alice = HumanAddr("alice".to_string());
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let private_meta = Metadata {
            name: Some("Name1".to_string()),
            description: Some("PrivDesc1".to_string()),
            image: Some("PrivUri1".to_string()),
        };
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: None,
            private_metadata: Some(private_meta.clone()),
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test global approval on token
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::PrivateMetadata {
                name,
                description,
                image,
            } => {
                assert_eq!(name, private_meta.name);
                assert_eq!(description, private_meta.description);
                assert_eq!(image, private_meta.image);
            }
            _ => panic!("unexpected"),
        }

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test global approval on all tokens
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::PrivateMetadata {
                name,
                description,
                image,
            } => {
                assert_eq!(name, private_meta.name);
                assert_eq!(description, private_meta.description);
                assert_eq!(image, private_meta.image);
            }
            _ => panic!("unexpected"),
        }

        let (init_result, mut deps) =
            init_helper_with_config(false, false, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "bkey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);

        let private_meta = Metadata {
            name: Some("Name1".to_string()),
            description: Some("PrivDesc1".to_string()),
            image: Some("PrivUri1".to_string()),
        };
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: None,
            private_metadata: Some(private_meta.clone()),
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // test trying to view sealed metadata
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: "akey".to_string(),
            }),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains(
            "Sealed metadata must be unwrapped by calling Reveal before it can be viewed"
        ));
        let handle_msg = HandleMsg::Reveal {
            token_id: "NFT1".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // test owner viewing empty metadata after the private got unwrapped to public
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: "akey".to_string(),
            }),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::PrivateMetadata {
                name,
                description,
                image,
            } => {
                assert!(name.is_none());
                assert!(description.is_none());
                assert!(image.is_none());
            }
            _ => panic!("unexpected"),
        }

        // test viewer not permitted
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: bob.clone(),
                viewing_key: "bkey".to_string(),
            }),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("You are not authorized to perform this action on token NFT1"));
    }
}
