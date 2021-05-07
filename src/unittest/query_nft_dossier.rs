#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use crate::msg::{QueryMsg, HandleMsg, AccessLevel, QueryAnswer, ViewerInfo, Snip721Approval, HandleAnswer};
    use crate::contract::{query, handle};
    use crate::token::Metadata;
    use cosmwasm_std::{HumanAddr, Env, BlockInfo, MessageInfo, from_binary};
    use cosmwasm_std::testing::{mock_env, MOCK_CONTRACT_ADDR};
    use crate::expiration::Expiration;

    #[test]
    fn test_query_nft_dossier() {
        let (init_result, deps) =
            init_helper_with_config(true, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is public
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: None,
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

        // test token not found when supply is private
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("You are not authorized to perform this action on token NFT1"));

        let public_meta = Metadata {
            name: Some("Name1".to_string()),
            description: Some("PubDesc1".to_string()),
            image: Some("PubUri1".to_string()),
        };
        let private_meta = Metadata {
            name: Some("PrivName1".to_string()),
            description: Some("PrivDesc1".to_string()),
            image: Some("PrivUri1".to_string()),
        };
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: Some(public_meta.clone()),
            private_metadata: Some(private_meta.clone()),
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtHeight(5)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
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
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 10,
                    time: 100,
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

        // test viewer not given, contract has public ownership
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier {
                owner,
                public_metadata,
                private_metadata,
                display_private_metadata_error,
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
                inventory_approvals,
            } => {
                assert_eq!(owner, Some(alice.clone()));
                assert_eq!(public_metadata, Some(public_meta.clone()));
                assert!(private_metadata.is_none());
                assert_eq!(
                    display_private_metadata_error,
                    Some("You are not authorized to perform this action on token NFT1".to_string())
                );
                assert!(owner_is_public);
                assert_eq!(public_ownership_expiration, Some(Expiration::Never));
                assert!(!private_metadata_is_public);
                assert!(private_metadata_is_public_expiration.is_none());
                assert!(token_approvals.is_none());
                assert!(inventory_approvals.is_none());
            }
            _ => panic!("unexpected"),
        }

        // test viewer not given, contract has private ownership, but token ownership
        // and private metadata was made public
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: Some(public_meta.clone()),
            private_metadata: Some(private_meta.clone()),
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtHeight(5)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
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
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 1,
                    time: 100,
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

        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier {
                owner,
                public_metadata,
                private_metadata,
                display_private_metadata_error,
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
                inventory_approvals,
            } => {
                assert_eq!(owner, Some(alice.clone()));
                assert_eq!(public_metadata, Some(public_meta.clone()));
                assert_eq!(private_metadata, Some(private_meta.clone()));
                assert!(display_private_metadata_error.is_none());
                assert!(owner_is_public);
                assert_eq!(public_ownership_expiration, Some(Expiration::AtHeight(5)));
                assert!(private_metadata_is_public);
                assert_eq!(
                    private_metadata_is_public_expiration,
                    Some(Expiration::AtHeight(5))
                );
                assert!(token_approvals.is_none());
                assert!(inventory_approvals.is_none());
            }
            _ => panic!("unexpected"),
        }

        // test no viewer given, ownership and private metadata made public at the
        // inventory level
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            expires: Some(Expiration::AtHeight(5)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(1000)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(5)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 1,
                    time: 100,
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

        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier {
                owner,
                public_metadata,
                private_metadata,
                display_private_metadata_error,
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
                inventory_approvals,
            } => {
                assert_eq!(owner, Some(alice.clone()));
                assert_eq!(public_metadata, Some(public_meta.clone()));
                assert_eq!(private_metadata, Some(private_meta.clone()));
                assert!(display_private_metadata_error.is_none());
                assert!(owner_is_public);
                assert_eq!(public_ownership_expiration, Some(Expiration::AtHeight(5)));
                assert!(private_metadata_is_public);
                assert_eq!(
                    private_metadata_is_public_expiration,
                    Some(Expiration::AtTime(1000))
                );
                assert!(token_approvals.is_none());
                assert!(inventory_approvals.is_none());
            }
            _ => panic!("unexpected"),
        }

        // test owner is the viewer including expired
        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "key".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        let alice_viewing_key = match answer {
            HandleAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        };

        let viewer = ViewerInfo {
            address: alice.clone(),
            viewing_key: alice_viewing_key.clone(),
        };
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 10000,
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

        let bob_tok_app = Snip721Approval {
            address: bob.clone(),
            view_owner_expiration: None,
            view_private_metadata_expiration: Some(Expiration::Never),
            transfer_expiration: None,
        };
        let char_tok_app = Snip721Approval {
            address: charlie.clone(),
            view_owner_expiration: Some(Expiration::AtHeight(5)),
            view_private_metadata_expiration: None,
            transfer_expiration: None,
        };
        let bob_all_app = Snip721Approval {
            address: bob.clone(),
            view_owner_expiration: Some(Expiration::Never),
            view_private_metadata_expiration: None,
            transfer_expiration: Some(Expiration::Never),
        };
        let char_all_app = Snip721Approval {
            address: charlie.clone(),
            view_owner_expiration: None,
            view_private_metadata_expiration: None,
            transfer_expiration: Some(Expiration::AtHeight(5)),
        };
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: Some(viewer.clone()),
            include_expired: Some(true),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier {
                owner,
                public_metadata,
                private_metadata,
                display_private_metadata_error,
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
                inventory_approvals,
            } => {
                assert_eq!(owner, Some(alice.clone()));
                assert_eq!(public_metadata, Some(public_meta.clone()));
                assert_eq!(private_metadata, Some(private_meta.clone()));
                assert!(display_private_metadata_error.is_none());
                assert!(!owner_is_public);
                assert!(public_ownership_expiration.is_none());
                assert!(!private_metadata_is_public);
                assert!(private_metadata_is_public_expiration.is_none());
                let token_approvals = token_approvals.unwrap();
                assert_eq!(token_approvals.len(), 2);
                assert!(token_approvals.contains(&bob_tok_app));
                assert!(token_approvals.contains(&char_tok_app));
                let inventory_approvals = inventory_approvals.unwrap();
                assert_eq!(inventory_approvals.len(), 2);
                assert!(inventory_approvals.contains(&bob_all_app));
                assert!(inventory_approvals.contains(&char_all_app));
            }
            _ => panic!("unexpected"),
        }
        // test owner is the viewer, filtering expired
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: Some(viewer.clone()),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier {
                owner,
                public_metadata,
                private_metadata,
                display_private_metadata_error,
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
                inventory_approvals,
            } => {
                assert_eq!(owner, Some(alice.clone()));
                assert_eq!(public_metadata, Some(public_meta.clone()));
                assert_eq!(private_metadata, Some(private_meta.clone()));
                assert!(display_private_metadata_error.is_none());
                assert!(!owner_is_public);
                assert!(public_ownership_expiration.is_none());
                assert!(!private_metadata_is_public);
                assert!(private_metadata_is_public_expiration.is_none());
                let token_approvals = token_approvals.unwrap();
                assert_eq!(token_approvals.len(), 1);
                assert!(token_approvals.contains(&bob_tok_app));
                assert!(!token_approvals.contains(&char_tok_app));
                let inventory_approvals = inventory_approvals.unwrap();
                assert_eq!(inventory_approvals.len(), 1);
                assert!(inventory_approvals.contains(&bob_all_app));
                assert!(!inventory_approvals.contains(&char_all_app));
            }
            _ => panic!("unexpected"),
        }

        // test bad viewing key
        let viewer = ViewerInfo {
            address: alice.clone(),
            viewing_key: "ky".to_string(),
        };
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: Some(viewer.clone()),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Wrong viewing key for this address or viewing key not set"));

        let (init_result, mut deps) =
            init_helper_with_config(false, false, true, true, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: Some(public_meta.clone()),
            private_metadata: Some(private_meta.clone()),
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "key".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        let alice_viewing_key = match answer {
            HandleAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        };

        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "ckey".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
        let answer: HandleAnswer = from_binary(&result.unwrap().data.unwrap()).unwrap();
        let charlie_viewing_key = match answer {
            HandleAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        };

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(5)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 10,
                    time: 100,
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

        // test owner is the viewer, but token is sealed
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: alice_viewing_key.clone(),
            }),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier {
                owner,
                public_metadata,
                private_metadata,
                display_private_metadata_error,
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
                inventory_approvals,
            } => {
                assert_eq!(owner, Some(alice.clone()));
                assert_eq!(public_metadata, Some(public_meta.clone()));
                assert!(private_metadata.is_none());
                assert_eq!(display_private_metadata_error, Some("Sealed metadata must be unwrapped by calling Reveal before it can be viewed".to_string()));
                assert!(!owner_is_public);
                assert!(public_ownership_expiration.is_none());
                assert!(!private_metadata_is_public);
                assert!(private_metadata_is_public_expiration.is_none());
                let token_approvals = token_approvals.unwrap();
                assert_eq!(token_approvals.len(), 1);
                assert!(token_approvals.contains(&bob_tok_app));
                assert!(!token_approvals.contains(&char_tok_app));
                let inventory_approvals = inventory_approvals.unwrap();
                assert_eq!(inventory_approvals.len(), 1);
                assert!(inventory_approvals.contains(&bob_all_app));
                assert!(!inventory_approvals.contains(&char_all_app));
            }
            _ => panic!("unexpected"),
        }
        let handle_msg = HandleMsg::Reveal {
            token_id: "NFT1".to_string(),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // test expired view private meta approval
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: charlie.clone(),
                viewing_key: charlie_viewing_key.clone(),
            }),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier {
                owner,
                public_metadata,
                private_metadata,
                display_private_metadata_error,
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
                inventory_approvals,
            } => {
                assert!(owner.is_none());
                assert_eq!(public_metadata, Some(public_meta.clone()));
                assert!(private_metadata.is_none());
                assert_eq!(
                    display_private_metadata_error,
                    Some("Access to token NFT1 has expired".to_string())
                );
                assert!(!owner_is_public);
                assert!(public_ownership_expiration.is_none());
                assert!(!private_metadata_is_public);
                assert!(private_metadata_is_public_expiration.is_none());
                assert!(token_approvals.is_none());
                assert!(inventory_approvals.is_none());
            }
            _ => panic!("unexpected"),
        }
    }
}
