#[cfg(test)]
mod tests {
    use crate::unittest::helpers::helpers::helpers::*;
    use crate::msg::{ContractStatus, HandleMsg, HandleAnswer};
    use crate::contract::handle;
    use cosmwasm_std::testing::mock_env;
    use cosmwasm_std::{from_binary, Api, HumanAddr};
    use cosmwasm_storage::ReadonlyPrefixedStorage;
    use crate::state::{PREFIX_VIEW_KEY, load};
    use crate::viewing_key::{VIEWING_KEY_SIZE, ViewingKey};


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

    #[test]
    fn test_set_viewing_key() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        // Viewing keys cannot be set, they must be generated
        set_contract_status(&mut deps, ContractStatus::StopTransactions);

        let handle_msg = HandleMsg::SetViewingKey {
            key: "blah".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let error = extract_error_msg(handle_result);
        assert!(error.contains("Viewing keys cannot be set, they must be generated"));
    }
}
