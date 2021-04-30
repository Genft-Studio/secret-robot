use cosmwasm_std::testing::{MockQuerier, MockApi, MockStorage, mock_dependencies, mock_env};
use cosmwasm_std::{StdResult, InitResponse, Extern, HumanAddr, from_binary, StdError, HandleResponse, Binary};
use crate::msg::{InitMsg, InitConfig};
use crate::contract::init;
use std::any::Any;

pub fn init_helper_default() -> (
    StdResult<InitResponse>,
    Extern<MockStorage, MockApi, MockQuerier>,
) {
    let mut deps = mock_dependencies(20, &[]);
    let env = mock_env("instantiator", &[]);

    let init_msg = InitMsg {
        name: "sec721".to_string(),
        symbol: "S721".to_string(),
        admin: Some(HumanAddr("admin".to_string())),
        entropy: "We're going to need a bigger boat".to_string(),
        config: None,
        post_init_callback: None,
    };

    (init(&mut deps, env, init_msg), deps)
}

pub fn init_helper_with_config(
    public_token_supply: bool,
    public_owner: bool,
    enable_sealed_metadata: bool,
    unwrapped_metadata_is_private: bool,
    minter_may_update_metadata: bool,
    owner_may_update_metadata: bool,
    enable_burn: bool,
) -> (
    StdResult<InitResponse>,
    Extern<MockStorage, MockApi, MockQuerier>,
) {
    let mut deps = mock_dependencies(20, &[]);

    let env = mock_env("instantiator", &[]);
    let init_config: InitConfig = from_binary(&Binary::from(
        format!(
            "{{\"public_token_supply\":{},
            \"public_owner\":{},
            \"enable_sealed_metadata\":{},
            \"unwrapped_metadata_is_private\":{},
            \"minter_may_update_metadata\":{},
            \"owner_may_update_metadata\":{},
            \"enable_burn\":{}}}",
            public_token_supply,
            public_owner,
            enable_sealed_metadata,
            unwrapped_metadata_is_private,
            minter_may_update_metadata,
            owner_may_update_metadata,
            enable_burn
        )
            .as_bytes(),
    ))
        .unwrap();
    let init_msg = InitMsg {
        name: "sec721".to_string(),
        symbol: "S721".to_string(),
        admin: Some(HumanAddr("admin".to_string())),
        entropy: "We're going to need a bigger boat".to_string(),
        config: Some(init_config),
        post_init_callback: None,
    };

    (init(&mut deps, env, init_msg), deps)
}

pub fn extract_error_msg<T: Any>(error: StdResult<T>) -> String {
    match error {
        Ok(_response) => panic!("Expected error, but had Ok response"),
        Err(err) => match err {
            StdError::GenericErr { msg, .. } => msg,
            #[allow(non_fmt_panic)]
            _ => panic!(format!("Unexpected error result {:?}", err)),
        },
    }
}

pub fn extract_log(resp: StdResult<HandleResponse>) -> String {
    match resp {
        Ok(response) => response.log[0].value.clone(),
        Err(_err) => "These are not the logs you are looking for".to_string(),
    }
}

pub fn init_helper_verified() -> Extern<MockStorage, MockApi, MockQuerier> {
    let (init_result, deps) = init_helper_default();
    assert!(
        init_result.is_ok(),
        "Init failed: {}",
        init_result.err().unwrap()
    );
    deps
}
