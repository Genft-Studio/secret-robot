#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use crate::msg::{QueryMsg};
    use crate::contract::{query};

    #[test]
    fn test_query_all_tokens() {
        let (init_result, deps) =
            init_helper_with_config(false, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::AllTokens {
            viewer: None,
            start_after: None,
            limit: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Tokens cannot be queried"));
    }
}
