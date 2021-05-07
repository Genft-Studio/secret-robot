#[cfg(test)]
mod tests {
    //TODO Split me

    use crate::contract::{handle, query};
    use crate::expiration::Expiration;
    use crate::msg::{AccessLevel, HandleMsg, QueryAnswer, QueryMsg, Snip721Approval, Tx, TxAction, HandleAnswer};
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{
        from_binary, BlockInfo, Env, HumanAddr, MessageInfo,
    };
    use crate::unittest_helpers::{init_helper_with_config};

    // test InventoryApprovals query
    #[test]
    fn test_inventory_approvals() {
        let (init_result, mut deps) =
            init_helper_with_config(false, true, false, false, true, false, true);
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


        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(1000000)),
            padding: None,
        };
        let _handle_result = handle(
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

        // test public ownership when contract has public ownership
        // and private metadata is public for all tokens
        let query_msg = QueryMsg::InventoryApprovals {
            address: alice.clone(),
            viewing_key: alice_viewing_key.clone(),
            include_expired: Some(true),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::InventoryApprovals {
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                inventory_approvals,
            } => {
                assert!(owner_is_public);
                assert_eq!(public_ownership_expiration, Some(Expiration::Never));
                assert!(private_metadata_is_public);
                assert_eq!(
                    private_metadata_is_public_expiration,
                    Some(Expiration::AtHeight(1000000))
                );
                assert!(inventory_approvals.is_empty());
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

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(2000000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let bob_approv = Snip721Approval {
            address: bob.clone(),
            view_owner_expiration: None,
            view_private_metadata_expiration: None,
            transfer_expiration: Some(Expiration::AtHeight(2000000)),
        };

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            expires: Some(Expiration::AtHeight(1000000)),
            padding: None,
        };
        let _handle_result = handle(
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

        // test owner makes ownership public for all tokens
        let query_msg = QueryMsg::InventoryApprovals {
            address: alice.clone(),
            viewing_key: alice_viewing_key.clone(),
            include_expired: Some(true),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::InventoryApprovals {
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                inventory_approvals,
            } => {
                assert!(owner_is_public);
                assert_eq!(
                    public_ownership_expiration,
                    Some(Expiration::AtHeight(1000000))
                );
                assert!(!private_metadata_is_public);
                assert!(private_metadata_is_public_expiration.is_none());
                assert_eq!(inventory_approvals, vec![bob_approv]);
            }
            _ => panic!("unexpected"),
        }
    }

    // test TransactionHistory query
    #[test]
    fn test_transaction_history() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let admin = HumanAddr("admin".to_string());
        let alice = HumanAddr("alice".to_string());
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

        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "key".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        let admin_viewing_key = match answer {
            HandleAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        };

        // test no txs yet
        let query_msg = QueryMsg::TransactionHistory {
            address: admin.clone(),
            viewing_key: admin_viewing_key.clone(),
            page: None,
            page_size: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { txs } => {
                assert!(txs.is_empty());
            }
            _ => panic!("unexpected"),
        }
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: None,
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: None,
            public_metadata: None,
            private_metadata: None,
            memo: Some("Mint 2".to_string()),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::BurnNft {
            token_id: "NFT2".to_string(),
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let mint1 = Tx {
            tx_id: 0,
            blockheight: 12345,
            token_id: "NFT1".to_string(),
            memo: None,
            action: TxAction::Mint {
                minter: admin.clone(),
                recipient: admin.clone(),
            },
        };
        let mint2 = Tx {
            tx_id: 1,
            blockheight: 12345,
            token_id: "NFT2".to_string(),
            memo: Some("Mint 2".to_string()),
            action: TxAction::Mint {
                minter: admin.clone(),
                recipient: admin.clone(),
            },
        };
        let burn2 = Tx {
            tx_id: 2,
            blockheight: 12345,
            token_id: "NFT2".to_string(),
            memo: None,
            action: TxAction::Burn {
                owner: admin.clone(),
                burner: Some(alice.clone()),
            },
        };

        // sanity check for all txs
        let query_msg = QueryMsg::TransactionHistory {
            address: admin.clone(),
            viewing_key: admin_viewing_key.clone(),
            page: None,
            page_size: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { txs } => {
                assert_eq!(
                    txs,
                    vec![burn2.clone(), mint2.clone(), mint1.clone()]
                );
            }
            _ => panic!("unexpected"),
        }

        // test paginating so only see last 1
        let query_msg = QueryMsg::TransactionHistory {
            address: admin.clone(),
            viewing_key: admin_viewing_key.clone(),
            page: None,
            page_size: Some(1),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { txs } => {
                assert_eq!(txs, vec![burn2.clone()]);
            }
            _ => panic!("unexpected"),
        }

        // test paginating so only see 2nd one
        let query_msg = QueryMsg::TransactionHistory {
            address: admin.clone(),
            viewing_key: admin_viewing_key.clone(),
            page: Some(1),
            page_size: Some(1),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { txs } => {
                assert_eq!(txs, vec![mint2.clone()]);
            }
            _ => panic!("unexpected"),
        }

        // test tx was logged to all participants
        let query_msg = QueryMsg::TransactionHistory {
            address: alice.clone(),
            viewing_key: alice_viewing_key.clone(),
            page: None,
            page_size: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { txs } => {
                assert_eq!(txs, vec![burn2.clone()]);
            }
            _ => panic!("unexpected"),
        }
    }

    // test RegisteredCodeHash query
    #[test]
    fn test_query_registered_code_hash() {
        let (init_result, deps) =
            init_helper_with_config(false, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::RegisteredCodeHash {
            contract: HumanAddr("alice".to_string()),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RegisteredCodeHash {
                code_hash,
                also_implements_batch_receive_nft,
            } => {
                assert!(code_hash.is_none());
                assert!(!also_implements_batch_receive_nft)
            }
            _ => panic!("unexpected"),
        }

    }
}
