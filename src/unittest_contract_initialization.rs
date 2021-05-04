#[cfg(test)]
mod tests {
    use crate::contract::{init};
    use crate::msg::{ContractStatus, HandleMsg, InitMsg, PostInitCallback};
    use crate::state::{load, Config, CONFIG_KEY};
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{
        to_binary, Api, Coin, CosmosMsg,
        HumanAddr, InitResponse, Uint128, WasmMsg,
    };
    use crate::unittest_helpers::{init_helper_default, init_helper_with_config};

    #[test]
    fn test_contract_initialization() {
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
}
