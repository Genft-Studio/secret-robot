#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use cosmwasm_std::{HumanAddr, from_binary};
    use crate::msg::{HandleMsg, QueryMsg, QueryAnswer, HandleAnswer};
    use crate::contract::{handle, query};
    use cosmwasm_std::testing::mock_env;

    // test VerifyTransferApproval query
    #[test]
    fn test_verify_transfer_approval() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let charlie = HumanAddr("charlie".to_string());

        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "ckey".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        let viewing_key = match answer {
            HandleAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        };

        let nft1 = "NFT1".to_string();
        let nft2 = "NFT2".to_string();
        let nft3 = "NFT3".to_string();
        let nft4 = "NFT4".to_string();

        mint_generic_token(&mut deps,"NFT1");
        mint_generic_token(&mut deps,"NFT2");

        let query_msg = QueryMsg::VerifyTransferApproval {
            token_ids: vec![nft1.clone(), nft2.clone(), nft3.clone(), nft4.clone()],
            address: charlie.clone(),
            viewing_key: viewing_key.clone(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::VerifyTransferApproval {
                approved_for_all,
                first_unapproved_token,
            } => {
                assert!(!approved_for_all);
                assert_eq!(first_unapproved_token, Some(nft1));
            }
            _ => panic!("unexpected"),
        }

    }
}
