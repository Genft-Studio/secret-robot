#[cfg(test)]
mod tests {
    use crate::unittest_helpers::{init_helper_with_config, mint_generic_token};
    use cosmwasm_std::{HumanAddr, from_binary};
    use crate::msg::{HandleMsg, QueryMsg, QueryAnswer, AccessLevel, HandleAnswer};
    use crate::contract::{handle, query};
    use cosmwasm_std::testing::{mock_env};

    // test Tokens query
    #[test]
    fn test_query_tokens() {
        let (init_result, mut deps) =
            init_helper_with_config(false, true, false, false, true, false, true);
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

        mint_generic_token(&mut deps, "NFT1");
        mint_generic_token(&mut deps, "NFT2");
        mint_generic_token(&mut deps, "NFT3");
        mint_generic_token(&mut deps, "NFT4");
        mint_generic_token(&mut deps, "NFT5");
        mint_generic_token(&mut deps, "NFT6");

        // test contract has public ownership
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: None,
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

        let handle_msg = HandleMsg::MakeOwnershipPrivate { padding: None };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT5".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // test no key provided should only see public tokens
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: None,
            start_after: None,
            limit: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec!["NFT1".to_string(), "NFT3".to_string()];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }

        // test viewer with a a token permission sees that one and the public ones
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: Some(bob.clone()),
            viewing_key: Some(bkey.clone()),
            start_after: None,
            limit: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec!["NFT1".to_string(), "NFT3".to_string(), "NFT5".to_string()];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }

        // test paginating with the owner querying
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: Some(akey.clone()),
            start_after: None,
            limit: Some(3),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec!["NFT1".to_string(), "NFT2".to_string(), "NFT3".to_string()];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: Some(akey.clone()),
            start_after: Some("NFT34".to_string()),
            limit: Some(30),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec!["NFT4".to_string(), "NFT5".to_string(), "NFT6".to_string()];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }

        // test setting all tokens public
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: None,
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
    }
}
