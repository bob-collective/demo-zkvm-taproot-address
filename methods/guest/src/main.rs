// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]

use std::io::Read;

use ethabi::{Address, Bytes, ParamType, Token};
use risc0_zkvm::guest::env;
use taproot_derive::derive_address_zkvm;

risc0_zkvm::guest::entry!(main);


fn main() {
    // parse the input
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes).unwrap();
    let input = ethabi::decode(&[ParamType::Address, ParamType::Bytes], &input_bytes).unwrap();
    let evm_address: Address = input[0].clone().into_address().unwrap();
    let private_key: Bytes = input[1].clone().into_bytes().unwrap();

    // run the actual computation
    let taproot_address = Token::String(derive_address_zkvm(private_key));

    // Commit the journal that will be received by the application contract.
    // Encoded types should match the args expected by the application callback.
    env::commit_slice(&ethabi::encode(&[
        Token::Address(evm_address),
        taproot_address,
    ]));
}
