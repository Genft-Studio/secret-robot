#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use crate::msg::{ContractStatus, HandleMsg};
    use crate::contract::handle;
    use cosmwasm_std::testing::mock_env;
    use cosmwasm_std::{Api, HumanAddr};
    use cosmwasm_storage::ReadonlyPrefixedStorage;
    use crate::state::{PREFIX_OWNER_PRIV, may_load, load};

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
}
