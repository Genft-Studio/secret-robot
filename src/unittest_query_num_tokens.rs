#[cfg(test)]
mod tests {
    use crate::unittest_helpers::{init_helper_with_config, extract_error_msg};
    use crate::msg::{HandleMsg, QueryMsg, ViewerInfo, QueryAnswer, HandleAnswer};
    use cosmwasm_std::{HumanAddr, from_binary, Extern};
    use crate::contract::{handle, query};
    use cosmwasm_std::testing::{mock_env, MockStorage, MockApi, MockQuerier};
    use crate::unittest_minters::{mint_nft1_alice, mint_nft2_alice, mint_nft3_alice};

    #[test]
    fn test_query_num_tokens() {
        let (init_result, mut deps) =
            init_helper_with_config(false, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        mint_nft1_alice(&mut deps);
        mint_nft2_alice(&mut deps);

        // test non-minter attempt
        let admin = HumanAddr("admin".to_string());
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());

        let minters = vec![
            alice.clone(),
            bob.clone(),
            charlie.clone(),
            bob.clone(),
            alice.clone(),
        ];
        let handle_msg = HandleMsg::SetMinters {
            minters: minters.clone(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let query_msg = QueryMsg::NumTokens { viewer: None };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("The token supply of this contract is private"));

        // test minter with bad viewing key
        let viewer = ViewerInfo {
            address: alice.clone(),
            viewing_key: "key".to_string(),
        };
        let query_msg = QueryMsg::NumTokens {
            viewer: Some(viewer.clone()),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("The token supply of this contract is private"));

        let key = create_viewing_key(&mut deps);

        // test admin query
        let viewer = ViewerInfo {
            address: admin.clone(),
            viewing_key: key,
        };
        let query_msg = QueryMsg::NumTokens {
            viewer: Some(viewer.clone()),
        };
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NumTokens { count } => {
                assert_eq!(count, 2);
            }
            _ => panic!("unexpected"),
        }

        // test token supply public
        let (init_result, mut deps) =
            init_helper_with_config(true, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        mint_nft1_alice(&mut deps);
        mint_nft2_alice(&mut deps);
        mint_nft3_alice(&mut deps);

        let query_msg = QueryMsg::NumTokens {
            viewer: None,
        };
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NumTokens { count } => {
                assert_eq!(count, 3);
            }
            _ => panic!("unexpected"),
        }
    }

    fn create_viewing_key(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) -> String {
        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "blah".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let answer: HandleAnswer = from_binary(&handle_result.unwrap().data.unwrap()).unwrap();

        let key = match answer {
            HandleAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        };
        key
    }
}
