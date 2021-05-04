#[cfg(test)]
mod tests {
    use crate::unittest_helpers::{init_helper_with_config, extract_error_msg};
    use crate::msg::{QueryMsg, QueryAnswer, HandleMsg};
    use crate::contract::{query, handle};
    use cosmwasm_std::{from_binary, HumanAddr};
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
        let error = extract_error_msg(query_result);
        assert!(error.contains("Token ID: NFT1 not found"));

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
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftInfo {
                name,
                description,
                image,
            } => {
                assert!(name.is_none());
                assert!(description.is_none());
                assert!(image.is_none());
            }
            _ => panic!("unexpected"),
        }
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
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftInfo {
                name,
                description,
                image,
            } => {
                assert_eq!(name, public_meta.name);
                assert_eq!(description, public_meta.description);
                assert_eq!(image, public_meta.image);
            }
            _ => panic!("unexpected"),
        }
    }
}
