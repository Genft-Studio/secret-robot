#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use cosmwasm_std::{HumanAddr, from_binary};
    use crate::msg::{HandleMsg, AccessLevel, QueryMsg, QueryAnswer, ViewerInfo, HandleAnswer};
    use crate::contract::{handle, query};
    use cosmwasm_std::testing::mock_env;
    use crate::token::Metadata;

    // test AllNftInfo query
    #[test]
    fn test_all_nft_info() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "akey".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        let alice_viewing_key = match answer {
            HandleAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        };

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
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // test don't have permission to view owner, but should still be able to see
        // public metadata
        let query_msg = QueryMsg::AllNftInfo {
            token_id: "NFT1".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::AllNftInfo { access, info } => {
                assert!(access.owner.is_none());
                assert!(access.approvals.is_empty());
                assert_eq!(info, Some(public_meta.clone()));
            }
            _ => panic!("unexpected"),
        }

        mint_generic_token(&mut deps, "NFT2");

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // test owner viewing all nft info, the is no public metadata
        let query_msg = QueryMsg::AllNftInfo {
            token_id: "NFT2".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: alice_viewing_key.clone(),
            }),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::AllNftInfo { access, info } => {
                assert_eq!(access.owner, Some(alice.clone()));
                assert_eq!(access.approvals.len(), 1);
                assert!(info.is_none());
            }
            _ => panic!("unexpected"),
        }
    }
}
