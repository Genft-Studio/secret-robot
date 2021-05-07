#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use crate::msg::{QueryMsg};
    use crate::contract::{query};

    // test minters query
    #[test]
    fn test_query_minters() {
        let (init_result, deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::Minters {};
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Minting is not restricted, minter list not supported"));
    }
}
