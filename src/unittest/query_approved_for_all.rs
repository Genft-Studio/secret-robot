#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use cosmwasm_std::{HumanAddr, from_binary};
    use crate::msg::{HandleMsg, QueryMsg, QueryAnswer, Cw721Approval, HandleAnswer};
    use crate::contract::{handle, query};
    use cosmwasm_std::testing::mock_env;
    use crate::expiration::Expiration;

    // test ApprovedForAll query
    #[test]
    fn test_approved_for_all() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());

        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "akey".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        let viewing_key = match answer {
            HandleAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        };

        let handle_msg = HandleMsg::ApproveAll {
            operator: bob.clone(),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::ApproveAll {
            operator: charlie.clone(),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // test no viewing key supplied
        let query_msg = QueryMsg::ApprovedForAll {
            owner: alice.clone(),
            viewing_key: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ApprovedForAll { operators } => {
                assert!(operators.is_empty());
            }
            _ => panic!("unexpected"),
        }

        let bob_approv = Cw721Approval {
            spender: bob.clone(),
            expires: Expiration::Never,
        };
        let char_approv = Cw721Approval {
            spender: charlie.clone(),
            expires: Expiration::Never,
        };

        // sanity check
        let query_msg = QueryMsg::ApprovedForAll {
            owner: alice.clone(),
            viewing_key: Some(viewing_key.clone()),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ApprovedForAll { operators } => {
                assert_eq!(operators, vec![bob_approv, char_approv]);
            }
            _ => panic!("unexpected"),
        }
    }
}
