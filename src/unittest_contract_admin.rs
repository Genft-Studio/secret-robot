#[cfg(test)]
mod tests {
    use crate::unittest_helpers::{init_helper_default, set_contract_status, extract_error_msg};
    use crate::msg::{ContractStatus, HandleMsg};
    use cosmwasm_std::{HumanAddr, Api};
    use crate::contract::handle;
    use cosmwasm_std::testing::mock_env;
    use crate::state::{load, Config, CONFIG_KEY};

    // test add minters
    #[test]
    fn test_add_minters() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::AddMinters {
            minters: vec![],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Minting is not restricted, minter list not supported"));
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

        let handle_msg = HandleMsg::RemoveMinters {
            minters: vec![],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Minting is not restricted, minter list not supported"));
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

        let handle_msg = HandleMsg::SetMinters {
            minters: vec![],
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Minting is not restricted, minter list not supported"));
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
}
