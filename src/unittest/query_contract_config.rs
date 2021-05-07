#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use crate::msg::{QueryMsg, QueryAnswer};
    use crate::contract::query;
    use cosmwasm_std::from_binary;

    #[test]
    fn test_query_contract_config() {
        let (init_result, deps) =
            init_helper_with_config(false, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let query_msg = QueryMsg::ContractConfig {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ContractConfig {
                token_supply_is_public,
                owner_is_public,
                sealed_metadata_is_enabled,
                unwrapped_metadata_is_private,
                minter_may_update_metadata,
                owner_may_update_metadata,
                burn_is_enabled,
            } => {
                assert_eq!(token_supply_is_public, false);
                assert_eq!(owner_is_public, true);
                assert_eq!(sealed_metadata_is_enabled, true);
                assert_eq!(unwrapped_metadata_is_private, false);
                assert_eq!(minter_may_update_metadata, true);
                assert_eq!(owner_may_update_metadata, false);
                assert_eq!(burn_is_enabled, true);
            }
            _ => panic!("unexpected"),
        }
    }
}
