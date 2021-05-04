use cosmwasm_std::testing::{MockQuerier, MockApi, MockStorage, mock_dependencies, mock_env};
use cosmwasm_std::{StdResult, InitResponse, Extern, HumanAddr, from_binary, StdError, HandleResponse, Binary};
use crate::msg::{InitMsg, InitConfig, ContractStatus, HandleMsg, AccessLevel};
use crate::contract::{init, handle};
use std::any::Any;
use crate::token::Metadata;

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

pub fn set_contract_status(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>, status: ContractStatus) {
    let message = HandleMsg::SetContractStatus {
        level: status,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("admin", &[]), message);
    assert!(result.is_ok());
}

pub fn grant_all(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>, granter: &str, grantee: &str) {
    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr(grantee.to_string()),
        token_id: None,
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::All),
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env(granter, &[]), handle_msg);
    assert!(result.is_ok());
}

pub fn mint_nft1_alice_grant_bob_charlie(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT1".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: Some(AccessLevel::ApproveToken),
        expires: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("charlie".to_string()),
        token_id: Some("NFT1".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: None,
        transfer: Some(AccessLevel::ApproveToken),
        expires: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(handle_result.is_ok());
}

pub fn mint_nft2_alice_grant_charlie(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT2".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("charlie".to_string()),
        token_id: Some("NFT2".to_string()),
        view_owner: None,
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: None,
        expires: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(handle_result.is_ok());
}

pub fn mint_nft3_alice_grant_bob(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT3".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        private_metadata: Some(Metadata {
            name: Some("MyNFT3".to_string()),
            description: Some("privmetadata3".to_string()),
            image: Some("privuri3".to_string()),
        }),
        public_metadata: Some(Metadata {
            name: Some("MyNFT3".to_string()),
            description: Some("pubmetadata3".to_string()),
            image: Some("puburi3".to_string()),
        }),
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("bob".to_string()),
        token_id: Some("NFT3".to_string()),
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::ApproveToken),
        expires: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(handle_result.is_ok());
}

pub fn mint_nft4_bob_grant_alice(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT4".to_string()),
        owner: Some(HumanAddr("bob".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("alice".to_string()),
        token_id: Some("NFT4".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: None,
        transfer: None,
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(result.is_ok());
}

pub fn mint_nft5_bob_grant_alice_charlie(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT5".to_string()),
        owner: Some(HumanAddr("bob".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("alice".to_string()),
        token_id: Some("NFT5".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: None,
        transfer: Some(AccessLevel::ApproveToken),
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("charlie".to_string()),
        token_id: Some("NFT5".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: None,
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(result.is_ok());
}

pub fn mint_nft6_bob_grant_alice(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT6".to_string()),
        owner: Some(HumanAddr("bob".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("alice".to_string()),
        token_id: Some("NFT6".to_string()),
        view_owner: Some(AccessLevel::ApproveToken),
        view_private_metadata: Some(AccessLevel::ApproveToken),
        transfer: None,
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
    assert!(result.is_ok());
}

pub fn mint_nft7_charlie_grant_alice(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT7".to_string()),
        owner: Some(HumanAddr("charlie".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(handle_result.is_ok());

    let handle_msg = HandleMsg::SetWhitelistedApproval {
        address: HumanAddr("alice".to_string()),
        token_id: Some("NFT7".to_string()),
        view_owner: None,
        view_private_metadata: None,
        transfer: Some(AccessLevel::ApproveToken),
        expires: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(result.is_ok());
}

pub fn mint_nft8_charlie(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT8".to_string()),
        owner: Some(HumanAddr("charlie".to_string())),
        private_metadata: None,
        public_metadata: None,
        memo: None,
        padding: None,
    };
    let handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
    assert!(handle_result.is_ok());
}


pub fn mint_generic_token(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>, token_id: &str) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some(token_id.to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        public_metadata: None,
        private_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());
}
