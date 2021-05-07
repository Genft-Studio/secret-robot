use cosmwasm_std::{Extern, HumanAddr};
use cosmwasm_std::testing::{MockStorage, MockApi, MockQuerier, mock_env};
use crate::msg::HandleMsg;
use crate::token::Metadata;
use crate::contract::handle;

pub fn mint_nft1_alice(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
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
}

pub fn mint_nft2_alice(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
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
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());
}

pub fn mint_nft3_alice(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
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
}

pub fn _mint_nft4_alice(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
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
}

pub fn _mint_nft5_alice(mut deps: &mut Extern<MockStorage, MockApi, MockQuerier>) {
    let handle_msg = HandleMsg::MintNft {
        token_id: Some("NFT5".to_string()),
        owner: Some(HumanAddr("alice".to_string())),
        public_metadata: Some(Metadata {
            name: Some("My5".to_string()),
            description: Some("Public 5".to_string()),
            image: Some("URI 5".to_string()),
        }),
        private_metadata: None,
        memo: None,
        padding: None,
    };
    let result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
    assert!(result.is_ok());
}

