#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use cosmwasm_std::{HumanAddr, from_binary};
    use crate::msg::{HandleMsg, AccessLevel, QueryMsg, ViewerInfo, HandleAnswer};
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
        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "akey".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        let _akey = match answer {
            HandleAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        };

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
        let err = extract_error_msg(query_result);
        assert_eq!(err, "Token must be burned to retrieve metadata.");

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
        let err = extract_error_msg(query_result);
        assert_eq!(err, "Token must be burned to retrieve metadata.");

        let (init_result, mut deps) =
            init_helper_with_config(false, false, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "akey".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        let akey = match answer {
            HandleAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        };

        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "bkey".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        let bkey = match answer {
            HandleAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        };

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
                viewing_key: akey.clone(),
            }),
        };
        let query_result = query(&deps, query_msg);
        let err = extract_error_msg(query_result);
        assert_eq!(err, "Token must be burned to retrieve metadata.");

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
                viewing_key: akey.clone(),
            }),
        };
        let query_result = query(&deps, query_msg);
        let err = extract_error_msg(query_result);
        assert_eq!(err, "Token must be burned to retrieve metadata.");

        // test viewer not permitted
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: bob.clone(),
                viewing_key: bkey.clone(),
            }),
        };
        let query_result = query(&deps, query_msg);
        let err = extract_error_msg(query_result);
        assert_eq!(err, "Token must be burned to retrieve metadata.");
    }
}
