#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use cosmwasm_std::{HumanAddr, Env, BlockInfo, MessageInfo, from_binary};
    use crate::msg::{QueryMsg, HandleMsg, AccessLevel, Snip721Approval, QueryAnswer, HandleAnswer};
    use crate::contract::{query, handle};
    use cosmwasm_std::testing::{mock_env, MOCK_CONTRACT_ADDR};
    use crate::expiration::Expiration;

    // test TokenApprovals query
    #[test]
    fn test_token_approvals() {
        let (init_result, deps) =
            init_helper_with_config(true, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let bob = HumanAddr("bob".to_string());

        // test token not found when supply is public
        let query_msg = QueryMsg::TokenApprovals {
            token_id: "NFT1".to_string(),
            viewing_key: "akey".to_string(),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Token ID: NFT1 not found"));

        let (init_result, mut deps) =
            init_helper_with_config(false, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "akey".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        let akey = match answer {
            HandleAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        };

        // test token not found when supply is private
        let query_msg = QueryMsg::TokenApprovals {
            token_id: "NFT1".to_string(),
            viewing_key: akey.clone(),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("You are not authorized to view approvals for token NFT1"));

        mint_generic_token(&mut deps, "NFT1");

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(2000000)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let bob_approv = Snip721Approval {
            address: bob.clone(),
            view_owner_expiration: None,
            view_private_metadata_expiration: Some(Expiration::Never),
            transfer_expiration: None,
        };

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtHeight(1000000)),
            padding: None,
        };
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 500,
                    time: 1000000,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        assert!(result.is_ok());

        // test public ownership when contract has public ownership
        // and private meta is public on the token
        let query_msg = QueryMsg::TokenApprovals {
            token_id: "NFT1".to_string(),
            viewing_key: akey.clone(),
            include_expired: Some(true),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenApprovals {
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
            } => {
                assert!(owner_is_public);
                assert_eq!(public_ownership_expiration, Some(Expiration::Never));
                assert!(private_metadata_is_public);
                assert_eq!(
                    private_metadata_is_public_expiration,
                    Some(Expiration::AtHeight(1000000))
                );
                assert_eq!(token_approvals, vec![bob_approv.clone()]);
            }
            _ => panic!("unexpected"),
        }
        let handle_msg = HandleMsg::MakeOwnershipPrivate { padding: None };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(1000000)),
            padding: None,
        };
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 500,
                    time: 1000000,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        assert!(result.is_ok());

        // test token has public ownership
        // and private meta is public for all of alice's tokens
        let query_msg = QueryMsg::TokenApprovals {
            token_id: "NFT1".to_string(),
            viewing_key: akey.clone(),
            include_expired: Some(true),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenApprovals {
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
            } => {
                assert!(owner_is_public);
                assert_eq!(
                    public_ownership_expiration,
                    Some(Expiration::AtHeight(1000000))
                );
                assert!(private_metadata_is_public);
                assert_eq!(
                    private_metadata_is_public_expiration,
                    Some(Expiration::AtHeight(1000000))
                );
                assert_eq!(token_approvals, vec![bob_approv.clone()]);
            }
            _ => panic!("unexpected"),
        }

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: Some(AccessLevel::None),
            expires: Some(Expiration::AtHeight(2000000)),
            padding: None,
        };
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 500,
                    time: 1000000,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        assert!(result.is_ok());

        // test all of alice's tokens have public ownership
        let query_msg = QueryMsg::TokenApprovals {
            token_id: "NFT1".to_string(),
            viewing_key: akey.clone(),
            include_expired: Some(true),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenApprovals {
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
            } => {
                assert!(owner_is_public);
                assert_eq!(
                    public_ownership_expiration,
                    Some(Expiration::AtHeight(2000000))
                );
                assert!(!private_metadata_is_public);
                assert!(private_metadata_is_public_expiration.is_none());
                assert_eq!(token_approvals, vec![bob_approv.clone()]);
            }
            _ => panic!("unexpected"),
        }
    }
}
