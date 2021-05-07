#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use crate::msg::{HandleMsg, ContractStatus, AccessLevel};
    use cosmwasm_std::{HumanAddr, Api};
    use crate::contract::handle;
    use cosmwasm_std::testing::mock_env;
    use crate::state::{PermissionType, PREFIX_ALL_PERMISSIONS, Permission, json_load, PREFIX_INFOS, AuthList, load, PREFIX_AUTHLIST, may_load};
    use cosmwasm_storage::ReadonlyPrefixedStorage;
    use crate::expiration::Expiration;
    use crate::token::Token;

    // test revoke_all from the cw721 spec
    #[test]
    fn test_cw721_revoke_all() {
        let (init_result, mut deps) = init_helper_default();
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
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg); // test burn when status prevents it
        assert!(result.is_ok());

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // test trying to RevokeAll when status does not allow
        set_contract_status(&mut deps, ContractStatus::StopAll);

        let handle_msg = HandleMsg::RevokeAll {
            operator: HumanAddr("bob".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // setting approval is ok even during StopTransactions status
        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        let bob_raw = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let alice_raw = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let alice_key = alice_raw.as_slice();
        let view_owner_idx = PermissionType::ViewOwner.to_usize();
        let view_meta_idx = PermissionType::ViewMetadata.to_usize();
        let transfer_idx = PermissionType::Transfer.to_usize();
        let nft1_key = 0u32.to_le_bytes();
        let nft2_key = 1u32.to_le_bytes();
        let nft3_key = 2u32.to_le_bytes();

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
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
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm bob has transfer token permissions but not transfer all permission
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::Never)
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        // confirm NFT1 permission has bob
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
            Some(Expiration::Never)
        );
        // confirm NFT2 permission has bob
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
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
        // confirm NFT3 permission has bob
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
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
        // confirm AuthLists has bob
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

        // test that RevokeAll will remove all the token permissions
        let handle_msg = HandleMsg::RevokeAll {
            operator: HumanAddr("bob".to_string()),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm bob does not have transfer all permission
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::Never)
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        // confirm bob's NFT1 permission is gone
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm bob's NFT2 permission is gone
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm bob's NFT3 permission is gone
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm AuthLists no longer have bob
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());

        // grant bob transfer all permission to test if revoke all removes it
        let handle_msg = HandleMsg::ApproveAll {
            operator: HumanAddr("bob".to_string()),
            expires: None,
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm bob has transfer all permission
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::Never)
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_oper_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // now get rid of it
        let handle_msg = HandleMsg::RevokeAll {
            operator: HumanAddr("bob".to_string()),
            padding: None,
        };
        let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(result.is_ok());

        // confirm bob no longer has transfer all permission
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::Never)
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
    }
}
