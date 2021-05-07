#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use crate::msg::{HandleMsg, AccessLevel, QueryMsg, QueryAnswer, ViewerInfo, Cw721Approval, HandleAnswer};
    use cosmwasm_std::{HumanAddr, from_binary, Extern, Env, BlockInfo, MessageInfo};
    use crate::contract::{handle, query};
    use cosmwasm_std::testing::{mock_env, MockStorage, MOCK_CONTRACT_ADDR, MockApi, MockQuerier};
    use crate::expiration::Expiration;

    // test OwnerOf query
    #[test]
    fn test_owner_of() {
        let (init_result, mut deps) =
            init_helper_with_config(false, true, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        mint_generic_token(&mut deps, "NFT1");

        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(1000000)),
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

        // test no viewer given, contract has public ownership
        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::OwnerOf { owner, approvals } => {
                assert_eq!(owner, alice.clone());
                assert!(approvals.is_empty());
            }
            _ => panic!("unexpected"),
        }

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        mint_generic_token(&mut deps, "NFT1");

        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());

        let akey = set_viewing_key(&mut deps, "akey", "alice");
        let _bkey = set_viewing_key(&mut deps, "bkey", "bob");
        let ckey = set_viewing_key(&mut deps, "ckey", "charlie");

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: None,
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
            expires: Some(Expiration::AtHeight(100)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // test viewer with no approvals, but token has public ownership
        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: charlie.clone(),
                viewing_key: ckey.clone(),
            }),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::OwnerOf { owner, approvals } => {
                assert_eq!(owner, alice.clone());
                assert!(approvals.is_empty());
            }
            _ => panic!("unexpected"),
        }

        // test viewer with no approval, but owner has made all his token ownership public
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: charlie.clone(),
                viewing_key: ckey.clone(),
            }),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::OwnerOf { owner, approvals } => {
                assert_eq!(owner, alice.clone());
                assert!(approvals.is_empty());
            }
            _ => panic!("unexpected"),
        }

        // test not permitted to view owner
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::None),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: charlie.clone(),
                viewing_key: ckey.clone(),
            }),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("You are not authorized to view the owner of token NFT1"));

        // test owner can see approvals including expired
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(1000)),
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

        let bob_approv = Cw721Approval {
            spender: bob.clone(),
            expires: Expiration::AtHeight(100),
        };
        let char_approv = Cw721Approval {
            spender: charlie.clone(),
            expires: Expiration::AtHeight(1000),
        };

        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: akey.clone(),
            }),
            include_expired: Some(true),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::OwnerOf { owner, approvals } => {
                assert_eq!(owner, alice.clone());
                assert_eq!(approvals.len(), 2);
                assert_eq!(approvals, vec![bob_approv.clone(), char_approv.clone()])
            }
            _ => panic!("unexpected"),
        }

        // test excluding expired
        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: akey.clone(),
            }),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::OwnerOf { owner, approvals } => {
                assert_eq!(owner, alice.clone());
                assert_eq!(approvals, vec![char_approv.clone()])
            }
            _ => panic!("unexpected"),
        }
    }

    fn set_viewing_key(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>, key: &str, owner: &str) -> String {
        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: key.to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env(owner.to_string(), &[]), handle_msg);
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        match answer {
            HandleAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        }
    }
}
