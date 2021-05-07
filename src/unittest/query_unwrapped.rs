#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use crate::msg::{QueryMsg, QueryAnswer, HandleMsg};
    use crate::contract::{query, handle};
    use cosmwasm_std::{from_binary};
    use cosmwasm_std::testing::mock_env;

    // test IsUnwrapped query
    #[test]
    fn test_is_unwrapped() {
        let (init_result, deps) =
            init_helper_with_config(true, true, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is public and sealed meta is disabled
        let query_msg = QueryMsg::IsUnwrapped {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Token ID: NFT1 not found"));

        let (init_result, deps) =
            init_helper_with_config(false, true, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is private and sealed meta is disabled
        let query_msg = QueryMsg::IsUnwrapped {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::IsUnwrapped { token_is_unwrapped } => {
                assert!(token_is_unwrapped);
            }
            _ => panic!("unexpected"),
        }

        let (init_result, mut deps) =
            init_helper_with_config(false, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is private and sealed meta is enabled
        let query_msg = QueryMsg::IsUnwrapped {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::IsUnwrapped { token_is_unwrapped } => {
                assert!(!token_is_unwrapped);
            }
            _ => panic!("unexpected"),
        }
        mint_generic_token(&mut deps,"NFT1");

        // sanity check, token sealed
        let query_msg = QueryMsg::IsUnwrapped {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::IsUnwrapped { token_is_unwrapped } => {
                assert!(!token_is_unwrapped);
            }
            _ => panic!("unexpected"),
        }

        let handle_msg = HandleMsg::Reveal {
            token_id: "NFT1".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // sanity check, token unwrapped
        let query_msg = QueryMsg::IsUnwrapped {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::IsUnwrapped { token_is_unwrapped } => {
                assert!(token_is_unwrapped);
            }
            _ => panic!("unexpected"),
        }
    }
}
