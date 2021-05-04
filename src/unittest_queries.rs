#[cfg(test)]
mod tests {
    //TODO Split me

    use crate::contract::{handle, query};
    use crate::expiration::Expiration;
    use crate::msg::{
        AccessLevel, Cw721Approval, HandleMsg, QueryAnswer, QueryMsg,
        Snip721Approval, Tx, TxAction, ViewerInfo,
    };
    use crate::token::Metadata;
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{
        from_binary, BlockInfo, Env, HumanAddr, MessageInfo,
    };
    use crate::unittest_helpers::{extract_error_msg, init_helper_with_config};

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

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "bkey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "ckey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

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

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "bkey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "ckey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtHeight(100)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test viewer with no approvals, but token has public ownership
        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: charlie.clone(),
                viewing_key: "ckey".to_string(),
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
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: charlie.clone(),
                viewing_key: "ckey".to_string(),
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
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: charlie.clone(),
                viewing_key: "ckey".to_string(),
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
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(1000)),
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
                viewing_key: "akey".to_string(),
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
                viewing_key: "akey".to_string(),
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

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
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

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

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(alice.clone()),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test owner viewing all nft info, the is no public metadata
        let query_msg = QueryMsg::AllNftInfo {
            token_id: "NFT2".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: "akey".to_string(),
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

    // test PrivateMetadata query
    #[test]
    fn test_private_metadata() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let alice = HumanAddr("alice".to_string());
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let private_meta = Metadata {
            name: Some("Name1".to_string()),
            description: Some("PrivDesc1".to_string()),
            image: Some("PrivUri1".to_string()),
        };
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: None,
            private_metadata: Some(private_meta.clone()),
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test global approval on token
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::PrivateMetadata {
                name,
                description,
                image,
            } => {
                assert_eq!(name, private_meta.name);
                assert_eq!(description, private_meta.description);
                assert_eq!(image, private_meta.image);
            }
            _ => panic!("unexpected"),
        }

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test global approval on all tokens
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::PrivateMetadata {
                name,
                description,
                image,
            } => {
                assert_eq!(name, private_meta.name);
                assert_eq!(description, private_meta.description);
                assert_eq!(image, private_meta.image);
            }
            _ => panic!("unexpected"),
        }

        let (init_result, mut deps) =
            init_helper_with_config(false, false, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "bkey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);

        let private_meta = Metadata {
            name: Some("Name1".to_string()),
            description: Some("PrivDesc1".to_string()),
            image: Some("PrivUri1".to_string()),
        };
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: None,
            private_metadata: Some(private_meta.clone()),
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // test trying to view sealed metadata
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: "akey".to_string(),
            }),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains(
            "Sealed metadata must be unwrapped by calling Reveal before it can be viewed"
        ));
        let handle_msg = HandleMsg::Reveal {
            token_id: "NFT1".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test owner viewing empty metadata after the private got unwrapped to public
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: "akey".to_string(),
            }),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::PrivateMetadata {
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

        // test viewer not permitted
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: bob.clone(),
                viewing_key: "bkey".to_string(),
            }),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("You are not authorized to perform this action on token NFT1"));
    }

    // test ApprovedForAll query
    #[test]
    fn test_approved_for_all() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());

        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::ApproveAll {
            operator: bob.clone(),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::ApproveAll {
            operator: charlie.clone(),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test no viewing key supplied
        let query_msg = QueryMsg::ApprovedForAll {
            owner: alice.clone(),
            viewing_key: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ApprovedForAll { operators } => {
                assert!(operators.is_empty());
            }
            _ => panic!("unexpected"),
        }

        let bob_approv = Cw721Approval {
            spender: bob.clone(),
            expires: Expiration::Never,
        };
        let char_approv = Cw721Approval {
            spender: charlie.clone(),
            expires: Expiration::Never,
        };

        // sanity check
        let query_msg = QueryMsg::ApprovedForAll {
            owner: alice.clone(),
            viewing_key: Some("akey".to_string()),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ApprovedForAll { operators } => {
                assert_eq!(operators, vec![bob_approv, char_approv]);
            }
            _ => panic!("unexpected"),
        }
    }

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

        let alice = HumanAddr("alice".to_string());
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
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test token not found when supply is private
        let query_msg = QueryMsg::TokenApprovals {
            token_id: "NFT1".to_string(),
            viewing_key: "akey".to_string(),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("You are not authorized to view approvals for token NFT1"));

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

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
        // and private meta is public on the token
        let query_msg = QueryMsg::TokenApprovals {
            token_id: "NFT1".to_string(),
            viewing_key: "akey".to_string(),
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
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
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

        // test token has public ownership
        // and private meta is public for all of alice's tokens
        let query_msg = QueryMsg::TokenApprovals {
            token_id: "NFT1".to_string(),
            viewing_key: "akey".to_string(),
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
        // test all of alice's tokens have public ownership
        let query_msg = QueryMsg::TokenApprovals {
            token_id: "NFT1".to_string(),
            viewing_key: "akey".to_string(),
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

        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

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
            viewing_key: "akey".to_string(),
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

        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
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
            viewing_key: "akey".to_string(),
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

        let alice = HumanAddr("alice".to_string());
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

        let handle_msg = HandleMsg::MintNft {
            token_id: Some(nft1.clone()),
            owner: Some(alice.clone()),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some(nft2.clone()),
            owner: Some(alice.clone()),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some(nft3.clone()),
            owner: Some(bob.clone()),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some(nft4.clone()),
            owner: Some(charlie.clone()),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some(nft5.clone()),
            owner: Some(david.clone()),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: Some(nft3.clone()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);

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
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let handle_msg = HandleMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // test no txs yet
        let query_msg = QueryMsg::TransactionHistory {
            address: admin.clone(),
            viewing_key: "key".to_string(),
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: None,
            public_metadata: None,
            private_metadata: None,
            memo: Some("Mint 2".to_string()),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::TransferNft {
            token_id: "NFT1".to_string(),
            recipient: alice.clone(),
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::BurnNft {
            token_id: "NFT2".to_string(),
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

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
        let xfer1 = Tx {
            tx_id: 2,
            blockheight: 12345,
            token_id: "NFT1".to_string(),
            memo: None,
            action: TxAction::Transfer {
                from: admin.clone(),
                sender: None,
                recipient: alice.clone(),
            },
        };
        let burn2 = Tx {
            tx_id: 3,
            blockheight: 12345,
            token_id: "NFT2".to_string(),
            memo: None,
            action: TxAction::Burn {
                owner: admin.clone(),
                burner: None,
            },
        };

        // sanity check for all txs
        let query_msg = QueryMsg::TransactionHistory {
            address: admin.clone(),
            viewing_key: "key".to_string(),
            page: None,
            page_size: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { txs } => {
                assert_eq!(
                    txs,
                    vec![burn2.clone(), xfer1.clone(), mint2.clone(), mint1.clone()]
                );
            }
            _ => panic!("unexpected"),
        }

        // test paginating so only see last 2
        let query_msg = QueryMsg::TransactionHistory {
            address: admin.clone(),
            viewing_key: "key".to_string(),
            page: None,
            page_size: Some(2),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { txs } => {
                assert_eq!(txs, vec![burn2.clone(), xfer1.clone()]);
            }
            _ => panic!("unexpected"),
        }

        // test paginating so only see 3rd one
        let query_msg = QueryMsg::TransactionHistory {
            address: admin.clone(),
            viewing_key: "key".to_string(),
            page: Some(2),
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
            viewing_key: "akey".to_string(),
            page: None,
            page_size: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { txs } => {
                assert_eq!(txs, vec![xfer1.clone()]);
            }
            _ => panic!("unexpected"),
        }
    }

    // test RegisteredCodeHash query
    #[test]
    fn test_query_registered_code_hash() {
        let (init_result, mut deps) =
            init_helper_with_config(false, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test not registered
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

        let handle_msg = HandleMsg::RegisterReceiveNft {
            code_hash: "Code Hash".to_string(),
            also_implements_batch_receive_nft: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // sanity check with default for implements BatchReceiveNft
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
                assert_eq!(code_hash, Some("Code Hash".to_string()));
                assert!(!also_implements_batch_receive_nft)
            }
            _ => panic!("unexpected"),
        }

        // sanity check with implementing BatchRegisterReceive
        let handle_msg = HandleMsg::RegisterReceiveNft {
            code_hash: "Code Hash".to_string(),
            also_implements_batch_receive_nft: Some(true),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);

        let query_msg = QueryMsg::RegisteredCodeHash {
            contract: HumanAddr("bob".to_string()),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RegisteredCodeHash {
                code_hash,
                also_implements_batch_receive_nft,
            } => {
                assert_eq!(code_hash, Some("Code Hash".to_string()));
                assert!(also_implements_batch_receive_nft)
            }
            _ => panic!("unexpected"),
        }
    }
}
