#[cfg(test)]
mod tests {
    use crate::unittest_helpers::init_helper_default;
    use crate::msg::{QueryMsg, QueryAnswer};
    use crate::contract::query;
    use cosmwasm_std::from_binary;

    #[test]
    fn test_query_contract_info() {
        let (init_result, deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let query_msg = QueryMsg::ContractInfo {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ContractInfo { name, symbol } => {
                assert_eq!(name, "sec721".to_string());
                assert_eq!(symbol, "S721".to_string());
            }
            _ => panic!("unexpected"),
        }
    }
}
