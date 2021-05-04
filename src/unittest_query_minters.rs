#[cfg(test)]
mod tests {
    use crate::unittest_helpers::init_helper_default;
    use cosmwasm_std::{HumanAddr, from_binary};
    use crate::msg::{HandleMsg, QueryMsg, QueryAnswer};
    use crate::contract::{handle, query};
    use cosmwasm_std::testing::mock_env;

    // test minters query
    #[test]
    fn test_query_minters() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
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

        let query_msg = QueryMsg::Minters {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::Minters { minters } => {
                assert_eq!(minters.len(), 3);
                assert!(minters.contains(&alice));
                assert!(minters.contains(&bob));
                assert!(minters.contains(&charlie));
            }
            _ => panic!("unexpected"),
        }
    }
}
