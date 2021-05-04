#[cfg(test)]
mod tests {
    use crate::unittest_helpers::{init_helper_with_config, mint_generic_token};
    use cosmwasm_std::{HumanAddr, from_binary};
    use crate::msg::{HandleMsg, AccessLevel, QueryMsg, QueryAnswer};
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

        let _alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());
        let david = HumanAddr("david".to_string());

        let handle_msg = HandleMsg::SetViewingKey {
            key: "ckey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);

        let nft1 = "NFT1".to_string();
        let nft2 = "NFT2".to_string();
        let nft3 = "NFT3".to_string();
        let nft4 = "NFT4".to_string();
        let nft5 = "NFT5".to_string();

        mint_generic_token(&mut deps,"NFT1");
        mint_generic_token(&mut deps,"NFT2");
        let handle_msg = HandleMsg::MintNft {
            token_id: Some(nft3.clone()),
            owner: Some(bob.clone()),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::MintNft {
            token_id: Some(nft4.clone()),
            owner: Some(charlie.clone()),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::MintNft {
            token_id: Some(nft5.clone()),
            owner: Some(david.clone()),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("david", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: Some(nft3.clone()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(result.is_ok());

        // test that charlie can transfer nft1 and 2 with operator approval,
        // nft3 with token approval, and nft4 because he owns it
        let query_msg = QueryMsg::VerifyTransferApproval {
            token_ids: vec![nft1.clone(), nft2.clone(), nft3.clone(), nft4.clone()],
            address: charlie.clone(),
            viewing_key: "ckey".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::VerifyTransferApproval {
                approved_for_all,
                first_unapproved_token,
            } => {
                assert!(approved_for_all);
                assert!(first_unapproved_token.is_none());
            }
            _ => panic!("unexpected"),
        }

        // test an unknown token id
        let query_msg = QueryMsg::VerifyTransferApproval {
            token_ids: vec![
                nft1.clone(),
                nft2.clone(),
                "NFT10".to_string(),
                nft3.clone(),
                nft4.clone(),
            ],
            address: charlie.clone(),
            viewing_key: "ckey".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::VerifyTransferApproval {
                approved_for_all,
                first_unapproved_token,
            } => {
                assert!(!approved_for_all);
                assert_eq!(first_unapproved_token, Some("NFT10".to_string()));
            }
            _ => panic!("unexpected"),
        }

        // test not having approval on NFT5
        let query_msg = QueryMsg::VerifyTransferApproval {
            token_ids: vec![
                nft1.clone(),
                nft2.clone(),
                nft3.clone(),
                nft4.clone(),
                nft5.clone(),
            ],
            address: charlie.clone(),
            viewing_key: "ckey".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::VerifyTransferApproval {
                approved_for_all,
                first_unapproved_token,
            } => {
                assert!(!approved_for_all);
                assert_eq!(first_unapproved_token, Some("NFT5".to_string()));
            }
            _ => panic!("unexpected"),
        }
    }
}
