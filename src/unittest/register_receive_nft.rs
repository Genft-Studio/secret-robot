#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use crate::msg::{HandleMsg};
    use crate::contract::handle;
    use cosmwasm_std::testing::mock_env;

    // test register receive_nft
    #[test]
    fn test_register_receive_nft() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::RegisterReceiveNft {
            code_hash: "alice code hash".to_string(),
            also_implements_batch_receive_nft: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token transfer not permitted. ReceiveNft registration not supported."));
    }
}
