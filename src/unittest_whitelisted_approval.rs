#[cfg(test)]
mod tests {
    use crate::unittest_helpers::{init_helper_with_config, extract_error_msg, set_contract_status};
    use crate::msg::{HandleMsg, AccessLevel, ContractStatus};
    use cosmwasm_std::{HumanAddr, Api, Env, BlockInfo, MessageInfo};
    use crate::contract::handle;
    use cosmwasm_std::testing::{mock_env, MOCK_CONTRACT_ADDR};
    use crate::token::{Metadata, Token};
    use crate::expiration::Expiration;
    use crate::state::{PermissionType, PREFIX_ALL_PERMISSIONS, Permission, json_load, PREFIX_INFOS, PREFIX_PUB_META, PREFIX_PRIV_META, load, may_load, PREFIX_AUTHLIST, AuthList, json_may_load};
    use cosmwasm_storage::ReadonlyPrefixedStorage;

    // test owner setting approval for specific addresses
    #[test]
    fn test_set_whitelisted_approval() {
        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is public
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: NFT1 not found"));

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is private
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You do not own token NFT1"));

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My1".to_string()),
                description: Some("Public 1".to_string()),
                image: Some("URI 1".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My2".to_string()),
                description: Some("Public 2".to_string()),
                image: Some("URI 2".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg); // test burn when status prevents it
        assert!(result.is_ok());

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My3".to_string()),
                description: Some("Public 3".to_string()),
                image: Some("URI 3".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT4".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My4".to_string()),
                description: Some("Public 4".to_string()),
                image: Some("URI 4".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // test trying to set approval when status does not allow
        set_contract_status(&mut deps, ContractStatus::StopAll);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));
        // setting approval is ok even during StopTransactions status
        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        // only allow the owner to use SetWhitelistedApproval
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You do not own token NFT1"));

        // try approving a token without specifying which token
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains(
            "Attempted to grant/revoke permission for a token, but did not specify a token ID"
        ));

        // try revoking a token approval without specifying which token
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::RevokeToken),
            expires: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains(
            "Attempted to grant/revoke permission for a token, but did not specify a token ID"
        ));

        // sanity check
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let bob_raw = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let charlie_raw = deps
            .api
            .canonical_address(&HumanAddr("charlie".to_string()))
            .unwrap();
        let david_raw = deps
            .api
            .canonical_address(&HumanAddr("david".to_string()))
            .unwrap();
        let edmund_raw = deps
            .api
            .canonical_address(&HumanAddr("edmund".to_string()))
            .unwrap();
        let frank_raw = deps
            .api
            .canonical_address(&HumanAddr("frank".to_string()))
            .unwrap();
        let alice_raw = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let alice_key = alice_raw.as_slice();
        let view_owner_idx = PermissionType::ViewOwner.to_usize();
        let view_meta_idx = PermissionType::ViewMetadata.to_usize();
        let transfer_idx = PermissionType::Transfer.to_usize();
        // confirm ALL permission
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        // confirm NFT1 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let nft1_key = 0u32.to_le_bytes();
        let nft2_key = 1u32.to_le_bytes();
        let nft3_key = 2u32.to_le_bytes();
        let nft4_key = 3u32.to_le_bytes();
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft1_key).unwrap();
        assert_eq!(pub_meta.name, Some("My1".to_string()));
        assert_eq!(pub_meta.description, Some("Public 1".to_string()));
        assert_eq!(pub_meta.image, Some("URI 1".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft1_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists has bob with NFT1 permission
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());

        // verify it doesn't duplicate any entries if adding permissions that already
        // exist
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm ALL permission
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        // confirm NFT1 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft1_key).unwrap();
        assert_eq!(pub_meta.name, Some("My1".to_string()));
        assert_eq!(pub_meta.description, Some("Public 1".to_string()));
        assert_eq!(pub_meta.image, Some("URI 1".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft1_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists has bob with NFT1 permission
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());

        // verify changing an existing ALL expiration while adding token access
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT2".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtHeight(1000)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm ALL permission with new expiration
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(1000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        // confirm NFT2 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft2_key).unwrap();
        assert_eq!(pub_meta.name, Some("My2".to_string()));
        assert_eq!(pub_meta.description, Some("Public 2".to_string()));
        assert_eq!(pub_meta.image, Some("URI 2".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft2_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(1000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists added bob's NFT2 transfer permission
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&1u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());

        // verify default expiration of "never"
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT3".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm NFT3 permissions
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists added bob's nft3 transfer permission
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 3);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&1u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());

        // verify revoking a token permission that never existed doesn't break anything
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT4".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::RevokeToken),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm NFT4 permissions
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm AuthLists are correct
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 3);
        assert!(!bob_auth.tokens[transfer_idx].contains(&3u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("charlie".to_string()),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("david".to_string()),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(1500000)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("edmund".to_string()),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(2000)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // test revoking token permission
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::RevokeToken),
            // expiration is ignored when only performing revoking actions
            expires: Some(Expiration::AtTime(5)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm didn't affect ALL permissions
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 3);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(1000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        let david_oper_perm = all_perm.iter().find(|p| p.address == david_raw).unwrap();
        assert_eq!(
            david_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1500000))
        );
        assert_eq!(david_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(david_oper_perm.expirations[view_owner_idx], None);
        let edmund_oper_perm = all_perm.iter().find(|p| p.address == edmund_raw).unwrap();
        assert_eq!(
            edmund_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        assert_eq!(edmund_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(edmund_oper_perm.expirations[view_owner_idx], None);
        // confirm NFT2 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft2_key).unwrap();
        assert_eq!(pub_meta.name, Some("My2".to_string()));
        assert_eq!(pub_meta.description, Some("Public 2".to_string()));
        assert_eq!(pub_meta.image, Some("URI 2".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft2_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        assert!(token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .is_none());
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists still has bob, but not with NFT2 transfer permission
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 2);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(!bob_auth.tokens[transfer_idx].contains(&1u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());

        // test revoking a token permission when address has ALL permission removes the ALL
        // permission, and adds token permissions for all the other tokens not revoked
        // giving them the expiration of the removed ALL permission
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::RevokeToken),
            view_private_metadata: None,
            transfer: None,
            expires: Some(Expiration::AtTime(5)),
            padding: None,
        };
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 100,
                    time: 1000,
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

        // confirm only bob's ALL permission is gone
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 2);
        assert!(all_perm.iter().find(|p| p.address == bob_raw).is_none());
        let david_oper_perm = all_perm.iter().find(|p| p.address == david_raw).unwrap();
        assert_eq!(
            david_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1500000))
        );
        assert_eq!(david_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(david_oper_perm.expirations[view_owner_idx], None);
        let edmund_oper_perm = all_perm.iter().find(|p| p.address == edmund_raw).unwrap();
        assert_eq!(
            edmund_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        assert_eq!(edmund_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(edmund_oper_perm.expirations[view_owner_idx], None);
        // confirm NFT1 permission added view_owner for bob with the old ALL permission
        // expiration, and did not touch the existing transfer permission for bob
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(1000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft1_key).unwrap();
        assert_eq!(pub_meta.name, Some("My1".to_string()));
        assert_eq!(pub_meta.description, Some("Public 1".to_string()));
        assert_eq!(pub_meta.image, Some("URI 1".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft1_key).unwrap();
        assert!(priv_meta.is_none());
        // confirm NFT2 permission for bob and charlie
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(1000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[transfer_idx], None);
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        // confirm NFT3 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft3_key).unwrap();
        assert_eq!(pub_meta.name, Some("My3".to_string()));
        assert_eq!(pub_meta.description, Some("Public 3".to_string()));
        assert_eq!(pub_meta.image, Some("URI 3".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm NFT4 permission for bob
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(1000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[transfer_idx], None);
        // confirm AuthLists still has bob, but not with NFT3 view_owner permission
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 2);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert_eq!(bob_auth.tokens[view_owner_idx].len(), 3);
        assert!(bob_auth.tokens[view_owner_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_owner_idx].contains(&1u32));
        assert!(!bob_auth.tokens[view_owner_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_owner_idx].contains(&3u32));
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());

        // test revoking all view_owner permission
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            // will be ignored but specifying shouldn't screw anything up
            token_id: Some("NFT4".to_string()),
            view_owner: Some(AccessLevel::None),
            view_private_metadata: None,
            transfer: None,
            // will be ignored but specifying shouldn't screw anything up
            expires: Some(Expiration::AtTime(5)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm only bob's ALL permission is gone
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 2);
        assert!(all_perm.iter().find(|p| p.address == bob_raw).is_none());
        let david_oper_perm = all_perm.iter().find(|p| p.address == david_raw).unwrap();
        assert_eq!(
            david_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1500000))
        );
        assert_eq!(david_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(david_oper_perm.expirations[view_owner_idx], None);
        let edmund_oper_perm = all_perm.iter().find(|p| p.address == edmund_raw).unwrap();
        assert_eq!(
            edmund_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        assert_eq!(edmund_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(edmund_oper_perm.expirations[view_owner_idx], None);
        // confirm NFT1 removed view_owner permission for bob, and did not touch the existing
        // transfer permission for bob
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft1_key).unwrap();
        assert_eq!(pub_meta.name, Some("My1".to_string()));
        assert_eq!(pub_meta.description, Some("Public 1".to_string()));
        assert_eq!(pub_meta.image, Some("URI 1".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft1_key).unwrap();
        assert!(priv_meta.is_none());
        // confirm NFT2 permission removed bob but left and charlie
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        assert!(token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .is_none());
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        // confirm NFT3 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft3_key).unwrap();
        assert_eq!(pub_meta.name, Some("My3".to_string()));
        assert_eq!(pub_meta.description, Some("Public 3".to_string()));
        assert_eq!(pub_meta.image, Some("URI 3".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm NFT4 permission removed bob
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm AuthLists still has bob, but only for NFT1 and 3 transfer permission
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 2);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());

        // test if approving a token for an address that already has ALL permission does
        // nothing if the given expiration is the same
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("edmund".to_string()),
            token_id: Some("NFT4".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtHeight(2000)),
            padding: None,
        };
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 100,
                    time: 1000,
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

        // confirm edmund still has ALL permission
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 2);
        let edmund_oper_perm = all_perm.iter().find(|p| p.address == edmund_raw).unwrap();
        assert_eq!(
            edmund_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        assert_eq!(edmund_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(edmund_oper_perm.expirations[view_owner_idx], None);
        // confirm NFT4 permissions did not add edmund
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft4_key).unwrap();
        assert_eq!(pub_meta.name, Some("My4".to_string()));
        assert_eq!(pub_meta.description, Some("Public 4".to_string()));
        assert_eq!(pub_meta.image, Some("URI 4".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft4_key).unwrap();
        assert!(priv_meta.is_none());
        assert!(token.permissions.is_empty());
        // confirm edmund did not get added to AuthList
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 2);
        assert!(auth_list.iter().find(|a| a.address == edmund_raw).is_none());

        // test approving a token for an address that already has ALL permission updates that
        // token's permission's expiration, removes ALL permission, and sets token permission
        // for all other tokens using the ALL permission's expiration
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("edmund".to_string()),
            token_id: Some("NFT4".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtHeight(3000)),
            padding: None,
        };
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 100,
                    time: 1000,
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

        // confirm edmund's ALL permission is gone
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        assert!(all_perm.iter().find(|p| p.address == edmund_raw).is_none());
        let david_oper_perm = all_perm.iter().find(|p| p.address == david_raw).unwrap();
        assert_eq!(
            david_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1500000))
        );
        assert_eq!(david_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(david_oper_perm.expirations[view_owner_idx], None);
        // confirm NFT1 added permission for edmund,
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm NFT2 added permission for edmund,
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        assert!(token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .is_none());
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm NFT3 added permission for edmund and that the token data did not get modified
        // and did not touch the existing transfer permission for bob
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft3_key).unwrap();
        assert_eq!(pub_meta.name, Some("My3".to_string()));
        assert_eq!(pub_meta.description, Some("Public 3".to_string()));
        assert_eq!(pub_meta.image, Some("URI 3".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 2);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm NFT4 permission added edmund with input expiration
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(3000))
        );
        // confirm AuthLists added edmund for transferring on every tokens
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 3);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        let edmund_auth = auth_list.iter().find(|a| a.address == edmund_raw).unwrap();
        assert_eq!(edmund_auth.tokens[transfer_idx].len(), 4);
        assert!(edmund_auth.tokens[transfer_idx].contains(&0u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&1u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&2u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&3u32));
        assert!(edmund_auth.tokens[view_meta_idx].is_empty());
        assert!(edmund_auth.tokens[view_owner_idx].is_empty());

        // test that approving a token when the address has an expired ALL permission
        // deletes the ALL permission and performs like a regular ApproveToken (does not
        // add approve permission to all the other tokens)
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("david".to_string()),
            token_id: Some("NFT4".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::Never),
            padding: None,
        };
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 100,
                    time: 2000000,
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

        // confirm davids's ALL permission is gone
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let may_oper: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
        assert!(may_oper.is_none());
        // confirm NFT3 did not add permission for david and that the token data did not get modified
        // and did not touch the existing transfer permission for bob
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft3_key).unwrap();
        assert_eq!(pub_meta.name, Some("My3".to_string()));
        assert_eq!(pub_meta.description, Some("Public 3".to_string()));
        assert_eq!(pub_meta.image, Some("URI 3".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 2);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm NFT4 permission added david with input expiration
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(3000))
        );
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm AuthLists added david for transferring on NFT4
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 4);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        let edmund_auth = auth_list.iter().find(|a| a.address == edmund_raw).unwrap();
        assert_eq!(edmund_auth.tokens[transfer_idx].len(), 4);
        assert!(edmund_auth.tokens[transfer_idx].contains(&0u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&1u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&2u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&3u32));
        assert!(edmund_auth.tokens[view_meta_idx].is_empty());
        assert!(edmund_auth.tokens[view_owner_idx].is_empty());
        let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[transfer_idx].len(), 1);
        assert!(david_auth.tokens[transfer_idx].contains(&3u32));
        assert!(david_auth.tokens[view_meta_idx].is_empty());
        assert!(david_auth.tokens[view_owner_idx].is_empty());

        // giving frank ALL permission for later test
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("frank".to_string()),
            // will be ignored but specifying shouldn't screw anything up
            token_id: Some("NFT4".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: None,
            expires: Some(Expiration::AtHeight(5000)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm frank's ALL permission
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let frank_oper_perm = all_perm.iter().find(|p| p.address == frank_raw).unwrap();
        assert_eq!(
            frank_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(5000))
        );
        assert_eq!(frank_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(frank_oper_perm.expirations[transfer_idx], None);
        // confirm NFT4 did not add permission for frank
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft4_key).unwrap();
        assert_eq!(pub_meta.name, Some("My4".to_string()));
        assert_eq!(pub_meta.description, Some("Public 4".to_string()));
        assert_eq!(pub_meta.image, Some("URI 4".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 2);
        assert!(token
            .permissions
            .iter()
            .find(|p| p.address == frank_raw)
            .is_none());
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(3000))
        );
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm AuthLists did not add frank
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 4);
        assert!(auth_list.iter().find(|a| a.address == frank_raw).is_none());
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        let edmund_auth = auth_list.iter().find(|a| a.address == edmund_raw).unwrap();
        assert_eq!(edmund_auth.tokens[transfer_idx].len(), 4);
        assert!(edmund_auth.tokens[transfer_idx].contains(&0u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&1u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&2u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&3u32));
        assert!(edmund_auth.tokens[view_meta_idx].is_empty());
        assert!(edmund_auth.tokens[view_owner_idx].is_empty());
        let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[transfer_idx].len(), 1);
        assert!(david_auth.tokens[transfer_idx].contains(&3u32));
        assert!(david_auth.tokens[view_meta_idx].is_empty());
        assert!(david_auth.tokens[view_owner_idx].is_empty());

        // test revoking a token permission when address has ALL permission removes the ALL
        // permission, and adds token permissions for all the other tokens not revoked
        // giving them the expiration of the removed ALL permission
        // This is same as above, but testing when the address has no AuthList already
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("frank".to_string()),
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::RevokeToken),
            view_private_metadata: None,
            transfer: None,
            // this will be ignored
            expires: Some(Expiration::AtTime(5)),
            padding: None,
        };
        let result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 100,
                    time: 1000,
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

        // confirm frank's ALL permission is gone
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
        assert!(all_perm.is_none());
        // confirm NFT1 permission added view_owner for frank with the old ALL permission
        // expiration
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 3);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        let frank_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == frank_raw)
            .unwrap();
        assert_eq!(
            frank_tok_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(5000))
        );
        assert_eq!(frank_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(frank_tok_perm.expirations[transfer_idx], None);
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft1_key).unwrap();
        assert_eq!(pub_meta.name, Some("My1".to_string()));
        assert_eq!(pub_meta.description, Some("Public 1".to_string()));
        assert_eq!(pub_meta.image, Some("URI 1".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft1_key).unwrap();
        assert!(priv_meta.is_none());
        // confirm NFT2 permission
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 3);
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        let frank_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == frank_raw)
            .unwrap();
        assert_eq!(
            frank_tok_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(5000))
        );
        assert_eq!(frank_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(frank_tok_perm.expirations[transfer_idx], None);
        // confirm NFT3 permissions do not include frank and that the token data did not get
        // modified
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft3_key).unwrap();
        assert_eq!(pub_meta.name, Some("My3".to_string()));
        assert_eq!(pub_meta.description, Some("Public 3".to_string()));
        assert_eq!(pub_meta.image, Some("URI 3".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 2);
        assert!(token
            .permissions
            .iter()
            .find(|p| p.address == frank_raw)
            .is_none());
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm NFT4 permission
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.permissions.len(), 3);
        let frank_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == frank_raw)
            .unwrap();
        assert_eq!(
            frank_tok_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(5000))
        );
        assert_eq!(frank_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(frank_tok_perm.expirations[transfer_idx], None);
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(3000))
        );
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists added frank with view_owner permissions for all butNFT3
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 5);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        let edmund_auth = auth_list.iter().find(|a| a.address == edmund_raw).unwrap();
        assert_eq!(edmund_auth.tokens[transfer_idx].len(), 4);
        assert!(edmund_auth.tokens[transfer_idx].contains(&0u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&1u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&2u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&3u32));
        assert!(edmund_auth.tokens[view_meta_idx].is_empty());
        assert!(edmund_auth.tokens[view_owner_idx].is_empty());
        let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[transfer_idx].len(), 1);
        assert!(david_auth.tokens[transfer_idx].contains(&3u32));
        assert!(david_auth.tokens[view_meta_idx].is_empty());
        assert!(david_auth.tokens[view_owner_idx].is_empty());
        let frank_auth = auth_list.iter().find(|a| a.address == frank_raw).unwrap();
        assert_eq!(frank_auth.tokens[view_owner_idx].len(), 3);
        assert!(frank_auth.tokens[view_owner_idx].contains(&0u32));
        assert!(frank_auth.tokens[view_owner_idx].contains(&1u32));
        assert!(frank_auth.tokens[view_owner_idx].contains(&3u32));
        assert!(frank_auth.tokens[view_meta_idx].is_empty());
        assert!(frank_auth.tokens[transfer_idx].is_empty());

        // test granting ALL permission when the address has some token permissions
        // This should remove all the token permissions and the AuthList
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("frank".to_string()),
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: None,
            expires: Some(Expiration::AtHeight(2500)),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm frank's ALL permission
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let frank_oper_perm = all_perm.iter().find(|p| p.address == frank_raw).unwrap();
        assert_eq!(
            frank_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(2500))
        );
        assert_eq!(frank_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(frank_oper_perm.expirations[transfer_idx], None);
        // confirm NFT1 permission removed frank
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        assert!(token
            .permissions
            .iter()
            .find(|p| p.address == frank_raw)
            .is_none());
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm NFT2 permission removed frank
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        assert!(token
            .permissions
            .iter()
            .find(|p| p.address == frank_raw)
            .is_none());
        // confirm NFT4 permission removed frank
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        assert!(token
            .permissions
            .iter()
            .find(|p| p.address == frank_raw)
            .is_none());
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(3000))
        );
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists removed frank
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 4);
        assert!(auth_list.iter().find(|a| a.address == frank_raw).is_none());
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        let edmund_auth = auth_list.iter().find(|a| a.address == edmund_raw).unwrap();
        assert_eq!(edmund_auth.tokens[transfer_idx].len(), 4);
        assert!(edmund_auth.tokens[transfer_idx].contains(&0u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&1u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&2u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&3u32));
        assert!(edmund_auth.tokens[view_meta_idx].is_empty());
        assert!(edmund_auth.tokens[view_owner_idx].is_empty());
        let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[transfer_idx].len(), 1);
        assert!(david_auth.tokens[transfer_idx].contains(&3u32));
        assert!(david_auth.tokens[view_meta_idx].is_empty());
        assert!(david_auth.tokens[view_owner_idx].is_empty());

        // test revoking all permissions when address has ALL
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("frank".to_string()),
            token_id: None,
            view_owner: Some(AccessLevel::None),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());
        // confirm frank's ALL permission is gone
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
        assert!(all_perm.is_none());
        // confirm NFT1 permission removed frank
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        assert!(token
            .permissions
            .iter()
            .find(|p| p.address == frank_raw)
            .is_none());
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm NFT2 permission removed frank
        assert!(token
            .permissions
            .iter()
            .find(|p| p.address == frank_raw)
            .is_none());
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        // confirm NFT4 permission removed frank
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        assert!(token
            .permissions
            .iter()
            .find(|p| p.address == frank_raw)
            .is_none());
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(3000))
        );
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists removed frank
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 4);
        assert!(auth_list.iter().find(|a| a.address == frank_raw).is_none());
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        let edmund_auth = auth_list.iter().find(|a| a.address == edmund_raw).unwrap();
        assert_eq!(edmund_auth.tokens[transfer_idx].len(), 4);
        assert!(edmund_auth.tokens[transfer_idx].contains(&0u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&1u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&2u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&3u32));
        assert!(edmund_auth.tokens[view_meta_idx].is_empty());
        assert!(edmund_auth.tokens[view_owner_idx].is_empty());
        let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[transfer_idx].len(), 1);
        assert!(david_auth.tokens[transfer_idx].contains(&3u32));
        assert!(david_auth.tokens[view_meta_idx].is_empty());
        assert!(david_auth.tokens[view_owner_idx].is_empty());

        // test revoking a token which is address' last permission
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("charlie".to_string()),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::RevokeToken),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm NFT2 permission removed charlie
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        assert!(token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .is_none());
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm AuthLists removed charlie
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert!(auth_list
            .iter()
            .find(|a| a.address == charlie_raw)
            .is_none());

        // verify that storage entry for AuthLists gets removed when all are gone
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::None),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("david".to_string()),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::None),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("edmund".to_string()),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::None),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // verify no ALL permissions left
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
        assert!(all_perm.is_none());
        // confirm NFT1 permissions are empty
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm NFT2 permissions are empty
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm NFT3 permissions are empty (and info is intact)
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft3_key).unwrap();
        assert_eq!(pub_meta.name, Some("My3".to_string()));
        assert_eq!(pub_meta.description, Some("Public 3".to_string()));
        assert_eq!(pub_meta.image, Some("URI 3".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert!(token.permissions.is_empty());
        // confirm NFT4 permissions are empty
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert!(token.permissions.is_empty());
        // verify no AuthLists left
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());

        // verify revoking doesn't break anything when there are no permissions
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("edmund".to_string()),
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::RevokeToken),
            view_private_metadata: None,
            transfer: Some(AccessLevel::None),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // verify no ALL permissions left
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
        assert!(all_perm.is_none());
        // confirm NFT1 permissions are empty
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm NFT2 permissions are empty
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm NFT3 permissions are empty (and info is intact)
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft3_key).unwrap();
        assert_eq!(pub_meta.name, Some("My3".to_string()));
        assert_eq!(pub_meta.description, Some("Public 3".to_string()));
        assert_eq!(pub_meta.image, Some("URI 3".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert!(token.permissions.is_empty());
        // confirm NFT4 permissions are empty
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert!(token.permissions.is_empty());
        // verify no AuthLists left
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());
    }
}
