#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use crate::msg::{QueryMsg, HandleMsg};
    use crate::contract::{query, handle};
    use cosmwasm_std::{HumanAddr};
    use crate::token::Metadata;
    use cosmwasm_std::testing::mock_env;

    // test NftInfo query
    #[test]
    fn test_nft_info() {
        let (init_result, deps) =
            init_helper_with_config(true, true, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is public
        let query_msg = QueryMsg::NftInfo {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let err = extract_error_msg(query_result);
        assert_eq!(err, "Token must be burned to retrieve metadata.");

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is public
        let query_msg = QueryMsg::NftInfo {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let err = extract_error_msg(query_result);
        assert_eq!(err, "Token must be burned to retrieve metadata.");

        let alice = HumanAddr("alice".to_string());
        let public_meta = Metadata {
            name: Some("Name1".to_string()),
            description: Some("PubDesc1".to_string()),
            image: Some("PubUri1".to_string()),
        };
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: Some(public_meta.clone()),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // sanity check
        let query_msg = QueryMsg::NftInfo {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let err = extract_error_msg(query_result);
        assert_eq!(err, "Token must be burned to retrieve metadata.");
    }
}
