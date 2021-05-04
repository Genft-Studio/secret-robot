#[cfg(test)]
mod tests {
    use crate::contract::{check_permission, handle, init};
    use crate::expiration::Expiration;
    use crate::msg::{
        AccessLevel, ContractStatus, HandleAnswer, HandleMsg, InitMsg,
        PostInitCallback,
    };
    use crate::state::{
        json_load, load, may_load, AuthList, Config, Permission,
        PermissionType, CONFIG_KEY, MINTERS_KEY, PREFIX_ALL_PERMISSIONS, PREFIX_AUTHLIST,
        PREFIX_INFOS, PREFIX_OWNER_PRIV,
        PREFIX_PRIV_META, PREFIX_PUB_META, PREFIX_RECEIVERS, PREFIX_VIEW_KEY,
    };
    use crate::token::{Metadata, Token};
    use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{
        from_binary, to_binary, Api, Binary, BlockInfo, CanonicalAddr, Coin, CosmosMsg,
        HumanAddr, InitResponse, Uint128, WasmMsg,
    };
    use cosmwasm_storage::ReadonlyPrefixedStorage;
    use crate::unittest_helpers::{init_helper_default, extract_error_msg, init_helper_with_config, set_contract_status};

    #[test]
    fn test_init_sanity() {
        // test default
        let (init_result, deps) = init_helper_default();
        assert_eq!(init_result.unwrap(), InitResponse::default());
        let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
        assert_eq!(config.status, ContractStatus::Normal.to_u8());
        assert_eq!(config.mint_cnt, 0);
        assert_eq!(config.tx_cnt, 0);
        assert_eq!(config.name, "sec721".to_string());
        assert_eq!(
            config.admin,
            deps.api
                .canonical_address(&HumanAddr("admin".to_string()))
                .unwrap()
        );
        assert_eq!(config.symbol, "S721".to_string());
        assert_eq!(config.token_supply_is_public, false);
        assert_eq!(config.owner_is_public, false);
        assert_eq!(config.sealed_metadata_is_enabled, false);
        assert_eq!(config.unwrap_to_private, false);
        assert_eq!(config.minter_may_update_metadata, true);
        assert_eq!(config.owner_may_update_metadata, false);
        assert_eq!(config.burn_is_enabled, false);

        // test config specification
        let (init_result, deps) =
            init_helper_with_config(true, true, true, true, false, true, false);
        assert_eq!(init_result.unwrap(), InitResponse::default());
        let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
        assert_eq!(config.status, ContractStatus::Normal.to_u8());
        assert_eq!(config.mint_cnt, 0);
        assert_eq!(config.tx_cnt, 0);
        assert_eq!(config.name, "sec721".to_string());
        assert_eq!(
            config.admin,
            deps.api
                .canonical_address(&HumanAddr("admin".to_string()))
                .unwrap()
        );
        assert_eq!(config.symbol, "S721".to_string());
        assert_eq!(config.token_supply_is_public, true);
        assert_eq!(config.owner_is_public, true);
        assert_eq!(config.sealed_metadata_is_enabled, true);
        assert_eq!(config.unwrap_to_private, true);
        assert_eq!(config.minter_may_update_metadata, false);
        assert_eq!(config.owner_may_update_metadata, true);
        assert_eq!(config.burn_is_enabled, false);

        // test post init callback
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);
        // just picking a random short HandleMsg that wouldn't really make sense
        let post_init_msg = to_binary(&HandleMsg::MakeOwnershipPrivate { padding: None }).unwrap();
        let post_init_send = vec![Coin {
            amount: Uint128(100),
            denom: "uscrt".to_string(),
        }];
        let post_init_callback = Some(PostInitCallback {
            msg: post_init_msg.clone(),
            contract_address: HumanAddr("spawner".to_string()),
            code_hash: "spawner hash".to_string(),
            send: post_init_send.clone(),
        });

        let init_msg = InitMsg {
            name: "sec721".to_string(),
            symbol: "S721".to_string(),
            admin: Some(HumanAddr("admin".to_string())),
            entropy: "We're going to need a bigger boat".to_string(),
            config: None,
            post_init_callback,
        };

        let init_response = init(&mut deps, env, init_msg).unwrap();
        assert_eq!(
            init_response.messages,
            vec![CosmosMsg::Wasm(WasmMsg::Execute {
                msg: post_init_msg,
                contract_addr: HumanAddr("spawner".to_string()),
                callback_code_hash: "spawner hash".to_string(),
                send: post_init_send,
            })]
        );
    }

    // Handle tests

    // test register receive_nft
    #[test]
    fn test_register_receive_nft() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test register when status prevents it
        set_contract_status(&mut deps, ContractStatus::StopAll);

        let handle_msg = HandleMsg::RegisterReceiveNft {
            code_hash: "alice code hash".to_string(),
            also_implements_batch_receive_nft: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still register when transactions are stopped
        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        // sanity check
        let handle_msg = HandleMsg::RegisterReceiveNft {
            code_hash: "alice code hash".to_string(),
            also_implements_batch_receive_nft: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let store = ReadonlyPrefixedStorage::new(PREFIX_RECEIVERS, &deps.storage);
        let hash: String = load(
            &store,
            deps.api
                .canonical_address(&HumanAddr("alice".to_string()))
                .unwrap()
                .as_slice(),
        )
            .unwrap();
        assert_eq!(&hash, "alice code hash");
    }

    // test create viewing key
    #[test]
    fn test_create_viewing_key() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test creating a key when status prevents it
        set_contract_status(&mut deps, ContractStatus::StopAll);

        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "blah".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still create a key when transactions are stopped
        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "blah".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let answer: HandleAnswer = from_binary(&handle_result.unwrap().data.unwrap()).unwrap();

        let key_str = match answer {
            HandleAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        };
        let key = ViewingKey(key_str);
        let alice_raw = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let key_store = ReadonlyPrefixedStorage::new(PREFIX_VIEW_KEY, &deps.storage);
        let saved_vk: [u8; VIEWING_KEY_SIZE] = load(&key_store, alice_raw.as_slice()).unwrap();
        assert!(key.check_viewing_key(&saved_vk));
    }

    // test set viewing key
    #[test]
    fn test_set_viewing_key() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test setting a key when status prevents it
        set_contract_status(&mut deps, ContractStatus::StopAll);

        let handle_msg = HandleMsg::SetViewingKey {
            key: "blah".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still set a key when transactions are stopped
        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        let handle_msg = HandleMsg::SetViewingKey {
            key: "blah".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let key = ViewingKey("blah".to_string());
        let alice_raw = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let key_store = ReadonlyPrefixedStorage::new(PREFIX_VIEW_KEY, &deps.storage);
        let saved_vk: [u8; VIEWING_KEY_SIZE] = load(&key_store, alice_raw.as_slice()).unwrap();
        assert!(key.check_viewing_key(&saved_vk));
    }

    // test add minters
    #[test]
    fn test_add_minters() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test adding minters when status prevents it
        set_contract_status(&mut deps, ContractStatus::StopAll);

        let minters = vec![
            HumanAddr("alice".to_string()),
            HumanAddr("bob".to_string()),
            HumanAddr("bob".to_string()),
            HumanAddr("alice".to_string()),
        ];
        let handle_msg = HandleMsg::AddMinters {
            minters: minters.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still add minters when transactions are stopped
        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        // test non admin trying to add minters
        let handle_msg = HandleMsg::AddMinters {
            minters: minters.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(
            error.contains("This is an admin command and can only be run from the admin address")
        );

        // sanity check
        let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
        let alice_raw = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let bob_raw = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let admin_raw = deps
            .api
            .canonical_address(&HumanAddr("admin".to_string()))
            .unwrap();
        // verify the minters we will add are not already in the list
        assert!(!cur_minter.contains(&alice_raw));
        assert!(!cur_minter.contains(&bob_raw));
        let handle_msg = HandleMsg::AddMinters {
            minters,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        // verify the new minters were added
        let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
        assert_eq!(cur_minter.len(), 3);
        assert!(cur_minter.contains(&alice_raw));
        assert!(cur_minter.contains(&bob_raw));
        assert!(cur_minter.contains(&admin_raw));

        // let's try an empty list to see if it breaks
        let minters = vec![];
        let handle_msg = HandleMsg::AddMinters {
            minters,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        // verify it's the same list
        let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
        assert_eq!(cur_minter.len(), 3);
        assert!(cur_minter.contains(&alice_raw));
        assert!(cur_minter.contains(&bob_raw));
        assert!(cur_minter.contains(&admin_raw));
    }

    // test remove minters
    #[test]
    fn test_remove_minters() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test removing minters when status prevents it
        set_contract_status(&mut deps, ContractStatus::StopAll);

        let minters = vec![
            HumanAddr("alice".to_string()),
            HumanAddr("bob".to_string()),
            HumanAddr("charlie".to_string()),
            HumanAddr("bob".to_string()),
        ];
        let handle_msg = HandleMsg::RemoveMinters {
            minters: minters.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still remove minters when transactions are stopped
        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        // test non admin trying to remove minters
        let handle_msg = HandleMsg::RemoveMinters {
            minters: minters.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(
            error.contains("This is an admin command and can only be run from the admin address")
        );

        // sanity check
        let alice_raw = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let bob_raw = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let charlie_raw = deps
            .api
            .canonical_address(&HumanAddr("charlie".to_string()))
            .unwrap();
        let admin_raw = deps
            .api
            .canonical_address(&HumanAddr("admin".to_string()))
            .unwrap();
        let handle_msg = HandleMsg::AddMinters {
            minters: minters.clone(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        // verify the new minters were added
        let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
        assert_eq!(cur_minter.len(), 4);
        assert!(cur_minter.contains(&alice_raw));
        assert!(cur_minter.contains(&bob_raw));
        assert!(cur_minter.contains(&charlie_raw));
        assert!(cur_minter.contains(&admin_raw));

        // let's give it an empty list to see if it breaks
        let minters = vec![];
        let handle_msg = HandleMsg::RemoveMinters {
            minters,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        // verify it is the same list
        let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
        assert_eq!(cur_minter.len(), 4);
        assert!(cur_minter.contains(&alice_raw));
        assert!(cur_minter.contains(&bob_raw));
        assert!(cur_minter.contains(&charlie_raw));
        assert!(cur_minter.contains(&admin_raw));

        // let's throw some repeats to see if it breaks
        let minters = vec![
            HumanAddr("alice".to_string()),
            HumanAddr("bob".to_string()),
            HumanAddr("alice".to_string()),
            HumanAddr("charlie".to_string()),
        ];
        let handle_msg = HandleMsg::RemoveMinters {
            minters,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        // verify the minters were removed
        let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
        assert_eq!(cur_minter.len(), 1);
        assert!(!cur_minter.contains(&alice_raw));
        assert!(!cur_minter.contains(&bob_raw));
        assert!(!cur_minter.contains(&charlie_raw));
        assert!(cur_minter.contains(&admin_raw));

        // let's remove the last one
        let handle_msg = HandleMsg::RemoveMinters {
            minters: vec![HumanAddr("admin".to_string())],
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        // verify the minters were removed
        let cur_minter: Option<Vec<CanonicalAddr>> = may_load(&deps.storage, MINTERS_KEY).unwrap();
        assert!(cur_minter.is_none());
    }

    // test set minters
    #[test]
    fn test_set_minters() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test setting minters when status prevents it
        set_contract_status(&mut deps, ContractStatus::StopAll);

        let minters = vec![
            HumanAddr("alice".to_string()),
            HumanAddr("bob".to_string()),
            HumanAddr("charlie".to_string()),
            HumanAddr("bob".to_string()),
            HumanAddr("alice".to_string()),
        ];
        let handle_msg = HandleMsg::SetMinters {
            minters: minters.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still set minters when transactions are stopped
        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        // test non admin trying to set minters
        let handle_msg = HandleMsg::SetMinters {
            minters: minters.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(
            error.contains("This is an admin command and can only be run from the admin address")
        );

        // sanity check
        let alice_raw = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let bob_raw = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let charlie_raw = deps
            .api
            .canonical_address(&HumanAddr("charlie".to_string()))
            .unwrap();
        let handle_msg = HandleMsg::SetMinters {
            minters: minters.clone(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        // verify the new minters were added
        let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
        assert_eq!(cur_minter.len(), 3);
        assert!(cur_minter.contains(&alice_raw));
        assert!(cur_minter.contains(&bob_raw));
        assert!(cur_minter.contains(&charlie_raw));
        // let's try an empty list
        let minters = vec![];
        let handle_msg = HandleMsg::SetMinters {
            minters,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        // verify the minters were removed
        let cur_minter: Option<Vec<CanonicalAddr>> = may_load(&deps.storage, MINTERS_KEY).unwrap();
        assert!(cur_minter.is_none());
    }

    // test change admin
    #[test]
    fn test_change_admin() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test changing admin when status prevents it
        set_contract_status(&mut deps, ContractStatus::StopAll);

        let handle_msg = HandleMsg::ChangeAdmin {
            address: HumanAddr("alice".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still change admin when transactions are stopped
        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        // test non admin trying to change admin
        let handle_msg = HandleMsg::ChangeAdmin {
            address: HumanAddr("alice".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(
            error.contains("This is an admin command and can only be run from the admin address")
        );

        // sanity check
        let alice_raw = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let admin_raw = deps
            .api
            .canonical_address(&HumanAddr("admin".to_string()))
            .unwrap();
        // verify admin is the current admin
        let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
        assert_eq!(config.admin, admin_raw);
        // change it to alice
        let handle_msg = HandleMsg::ChangeAdmin {
            address: HumanAddr("alice".to_string()),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        // verify admin was changed
        let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
        assert_eq!(config.admin, alice_raw);
    }

    // test set contract status
    #[test]
    fn test_set_contract_status() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test non admin trying to change status
        let handle_msg = HandleMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(
            error.contains("This is an admin command and can only be run from the admin address")
        );

        // sanity check
        // verify current status is normal
        let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
        assert_eq!(config.status, ContractStatus::Normal.to_u8());

        // change it to StopAll
        let handle_msg = HandleMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // verify status was changed
        let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
        assert_eq!(config.status, ContractStatus::StopAll.to_u8());
    }

    // test approve_all from the cw721 spec
    #[test]
    fn test_cw721_approve_all() {
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg); // test burn when status prevents it
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // test trying to ApproveAll when status does not allow
        set_contract_status(&mut deps, ContractStatus::StopAll);

        let handle_msg = HandleMsg::ApproveAll {
            operator: HumanAddr("bob".to_string()),
            expires: None,
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
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

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

        // test that ApproveAll will remove all the token permissions
        let handle_msg = HandleMsg::ApproveAll {
            operator: HumanAddr("bob".to_string()),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
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
    }

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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg); // test burn when status prevents it
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

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
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

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
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
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
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
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
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
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

    // test making ownership private
    #[test]
    fn test_make_ownership_private() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test setting privacy when status prevents it
        set_contract_status(&mut deps, ContractStatus::StopAll);

        let handle_msg = HandleMsg::MakeOwnershipPrivate { padding: None };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still set privacy when transactions are stopped
        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        // sanity check when contract default is private
        let handle_msg = HandleMsg::MakeOwnershipPrivate { padding: None };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let alice_raw = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let alice_key = alice_raw.as_slice();
        let store = ReadonlyPrefixedStorage::new(PREFIX_OWNER_PRIV, &deps.storage);
        let owner_priv: Option<bool> = may_load(&store, alice_key).unwrap();
        assert!(owner_priv.is_none());

        // test when contract default is public
        let (init_result, mut deps) =
            init_helper_with_config(false, true, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let handle_msg = HandleMsg::MakeOwnershipPrivate { padding: None };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let store = ReadonlyPrefixedStorage::new(PREFIX_OWNER_PRIV, &deps.storage);
        let owner_priv: bool = load(&store, alice_key).unwrap();
        assert!(!owner_priv);
    }

    // test owner setting global approvals
    #[test]
    fn test_set_global_approval() {
        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is public
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
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
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
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
                description: Some("Pub 1".to_string()),
                image: Some("URI 1".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // test trying to set approval when status does not allow
        set_contract_status(&mut deps, ContractStatus::StopAll);

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // setting approval is ok even during StopTransactions status
        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        // only allow the owner to use SetGlobalApproval
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You do not own token NFT1"));

        // try approving a token without specifying which token
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains(
            "Attempted to grant/revoke permission for a token, but did not specify a token ID"
        ));

        // try revoking a token approval without specifying which token
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::RevokeToken),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains(
            "Attempted to grant/revoke permission for a token, but did not specify a token ID"
        ));

        // sanity check
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let global_raw = CanonicalAddr(Binary::from(b"public"));
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
        let global_perm = all_perm.iter().find(|p| p.address == global_raw).unwrap();
        assert_eq!(
            global_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(global_perm.expirations[view_meta_idx], None);
        assert_eq!(global_perm.expirations[transfer_idx], None);
        // confirm NFT1 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let nft1_key = 0u32.to_le_bytes();
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &nft1_key).unwrap();
        assert_eq!(pub_meta.name, Some("My1".to_string()));
        assert_eq!(pub_meta.description, Some("Pub 1".to_string()));
        assert_eq!(pub_meta.image, Some("URI 1".to_string()));
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft1_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        let global_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == global_raw)
            .unwrap();
        assert_eq!(
            global_tok_perm.expirations[view_meta_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(global_tok_perm.expirations[transfer_idx], None);
        assert_eq!(global_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists has public with NFT1 permission
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let global_auth = auth_list.iter().find(|a| a.address == global_raw).unwrap();
        assert_eq!(global_auth.tokens[view_meta_idx].len(), 1);
        assert!(global_auth.tokens[view_meta_idx].contains(&0u32));
        assert!(global_auth.tokens[transfer_idx].is_empty());
        assert!(global_auth.tokens[view_owner_idx].is_empty());

        // bob approvals to make sure whitelisted addresses don't break
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let bob_raw = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        // confirm ALL permission
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 2);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        let global_perm = all_perm.iter().find(|p| p.address == global_raw).unwrap();
        assert_eq!(
            global_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(global_perm.expirations[view_meta_idx], None);
        assert_eq!(global_perm.expirations[transfer_idx], None);
        // confirm NFT1 permissions
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
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
        assert_eq!(
            global_tok_perm.expirations[view_meta_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(global_tok_perm.expirations[transfer_idx], None);
        assert_eq!(global_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists has bob with NFT1 permission
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 2);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let global_auth = auth_list.iter().find(|a| a.address == global_raw).unwrap();
        assert_eq!(global_auth.tokens[view_meta_idx].len(), 1);
        assert!(global_auth.tokens[view_meta_idx].contains(&0u32));
        assert!(global_auth.tokens[transfer_idx].is_empty());
        assert!(global_auth.tokens[view_owner_idx].is_empty());

        // confirm ALL permission
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 2);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        let global_perm = all_perm.iter().find(|p| p.address == global_raw).unwrap();
        assert_eq!(
            global_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(global_perm.expirations[view_meta_idx], None);
        assert_eq!(global_perm.expirations[transfer_idx], None);
        // confirm NFT1 permissions
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
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
        assert_eq!(
            global_tok_perm.expirations[view_meta_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(global_tok_perm.expirations[transfer_idx], None);
        assert_eq!(global_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists has bob with NFT1 permission
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 2);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let global_auth = auth_list.iter().find(|a| a.address == global_raw).unwrap();
        assert_eq!(global_auth.tokens[view_meta_idx].len(), 1);
        assert!(global_auth.tokens[view_meta_idx].contains(&0u32));
        assert!(global_auth.tokens[transfer_idx].is_empty());
        assert!(global_auth.tokens[view_owner_idx].is_empty());

        // test revoking global approval
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: Some(AccessLevel::None),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        // confirm ALL permission
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 2);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        let global_perm = all_perm.iter().find(|p| p.address == global_raw).unwrap();
        assert_eq!(
            global_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(global_perm.expirations[view_meta_idx], None);
        assert_eq!(global_perm.expirations[transfer_idx], None);
        // confirm NFT1 permissions
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
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
        let global_tok_perm = token.permissions.iter().find(|p| p.address == global_raw);
        assert!(global_tok_perm.is_none());
        // confirm AuthLists has bob with NFT1 permission
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, &deps.storage);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let global_auth = auth_list.iter().find(|a| a.address == global_raw);
        assert!(global_auth.is_none());
    }

    // test permissioning works
    #[test]
    fn test_check_permission() {
        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let block = BlockInfo {
            height: 1,
            time: 1,
            chain_id: "secret-2".to_string(),
        };
        let alice_raw = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let bob_raw = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let charlie_raw = deps
            .api
            .canonical_address(&HumanAddr("charlie".to_string()))
            .unwrap();
        let nft1_key = 0u32.to_le_bytes();
        let nft2_key = 1u32.to_le_bytes();
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My1".to_string()),
                description: Some("Pub 1".to_string()),
                image: Some("URI 1".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My2".to_string()),
                description: Some("Pub 2".to_string()),
                image: Some("URI 2".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // test not approved
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));

        // test owner is public for the contract
        let (init_result, mut deps) =
            init_helper_with_config(true, true, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My1".to_string()),
                description: Some("Pub 1".to_string()),
                image: Some("URI 1".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My2".to_string()),
                description: Some("Pub 2".to_string()),
                image: Some("URI 2".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            true,
        );
        assert!(check_perm.is_ok());

        // test owner makes their tokens private when the contract has public ownership
        let handle_msg = HandleMsg::MakeOwnershipPrivate { padding: None };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            true,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));

        // test owner later makes ownership of a single token public
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());
        // test public approval when no address is given
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            None,
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // test global approval for all tokens
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token2: Token = json_load(&info_store, &nft2_key).unwrap();
        let check_perm = check_permission(
            &deps,
            &block,
            &token2,
            "NFT2",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token2: Token = json_load(&info_store, &nft2_key).unwrap();
        let check_perm = check_permission(
            &deps,
            &block,
            &token2,
            "NFT2",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());
        // test public approval when no address is given
        let check_perm = check_permission(
            &deps,
            &block,
            &token2,
            "NFT2",
            None,
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // test those global permissions having expired
        let block = BlockInfo {
            height: 1,
            time: 2000000,
            chain_id: "secret-2".to_string(),
        };
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));
        let check_perm = check_permission(
            &deps,
            &block,
            &token2,
            "NFT2",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));

        let block = BlockInfo {
            height: 1,
            time: 1,
            chain_id: "secret-2".to_string(),
        };

        // test whitelisted approval on a token
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(5)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token2: Token = json_load(&info_store, &nft2_key).unwrap();
        let check_perm = check_permission(
            &deps,
            &block,
            &token2,
            "NFT2",
            Some(&bob_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());
        let check_perm = check_permission(
            &deps,
            &block,
            &token2,
            "NFT2",
            Some(&charlie_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));

        // test approval expired
        let block = BlockInfo {
            height: 1,
            time: 6,
            chain_id: "secret-2".to_string(),
        };
        let check_perm = check_permission(
            &deps,
            &block,
            &token2,
            "NFT2",
            Some(&bob_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("Access to token NFT2 has expired"));

        // test owner access
        let check_perm = check_permission(
            &deps,
            &block,
            &token2,
            "NFT2",
            Some(&alice_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // test whitelisted approval on all tokens
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("charlie".to_string()),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(7)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&charlie_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // test whitelisted ALL permission has expired
        let block = BlockInfo {
            height: 1,
            time: 7,
            chain_id: "secret-2".to_string(),
        };
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&charlie_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("Access to all tokens of alice has expired"));

        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My1".to_string()),
                description: Some("Pub 1".to_string()),
                image: Some("URI 1".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My2".to_string()),
                description: Some("Pub 2".to_string()),
                image: Some("URI 2".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // test whitelist approval expired, but global is good on a token
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: Some(Expiration::AtTime(10)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(1000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let block = BlockInfo {
            height: 1,
            time: 100,
            chain_id: "secret-2".to_string(),
        };
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // test whitelist approval expired, but global is good on ALL tokens
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: None,
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            transfer: None,
            expires: Some(Expiration::AtTime(10)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(1000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let block = BlockInfo {
            height: 1,
            time: 100,
            chain_id: "secret-2".to_string(),
        };
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // test whitelist approval is good, but global expired on a token
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: Some(Expiration::AtTime(1000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(10)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let block = BlockInfo {
            height: 1,
            time: 100,
            chain_id: "secret-2".to_string(),
        };
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // test whitelist approval is good, but global expired on ALL tokens
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: None,
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            transfer: None,
            expires: Some(Expiration::AtTime(10)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(1000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let block = BlockInfo {
            height: 1,
            time: 100,
            chain_id: "secret-2".to_string(),
        };
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My1".to_string()),
                description: Some("Pub 1".to_string()),
                image: Some("URI 1".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My2".to_string()),
                description: Some("Pub 2".to_string()),
                image: Some("URI 2".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // test bob has view owner approval on NFT1 and view metadata approval on ALL
        // while there is global view owner approval on ALL tokens and global view metadata
        // approval on NFT1
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("bob".to_string()),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::All),
            transfer: None,
            expires: Some(Expiration::AtTime(100)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(10)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let block = BlockInfo {
            height: 1,
            time: 1,
            chain_id: "secret-2".to_string(),
        };
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // now check where the global approvals expired
        let block = BlockInfo {
            height: 1,
            time: 50,
            chain_id: "secret-2".to_string(),
        };
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // throw a charlie transfer approval and a view meta token approval in the mix
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("charlie".to_string()),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(100)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: HumanAddr("charlie".to_string()),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: Some(Expiration::AtTime(100)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&charlie_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());
        let check_perm = check_permission(
            &deps,
            &block,
            &token1,
            "NFT1",
            Some(&charlie_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());
    }
}
