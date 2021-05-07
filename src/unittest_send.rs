#[cfg(test)]
mod tests {
    use cosmwasm_std::{HumanAddr};
    use cosmwasm_std::testing::{mock_env};

    use crate::contract::handle;
    use crate::msg::{HandleMsg, Transfer};
    use crate::unittest_helpers::{extract_error_msg, init_helper_with_config};

    #[test]
    fn test_send() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let handle_msg = HandleMsg::SendNft {
            contract: HumanAddr("bob".to_string()),
            token_id: "MyNFT".to_string(),
            msg: None,
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token transfer not permitted"));
    }

    #[test]
    fn test_batch_send() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let handle_msg = HandleMsg::BatchSendNft {
            sends: vec![],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token transfer not permitted"));
    }

    #[test]
    fn test_transfer() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let handle_msg = HandleMsg::TransferNft {
            recipient: HumanAddr("bob".to_string()),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token transfer not permitted"));
    }

    #[test]
    fn test_batch_transfer() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let transfers = vec![Transfer {
            recipient: HumanAddr("bob".to_string()),
            token_ids: vec!["MyNFT".to_string()],
            memo: None,
        }];
        let handle_msg = HandleMsg::BatchTransferNft {
            transfers,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token transfer not permitted"));
    }
}
