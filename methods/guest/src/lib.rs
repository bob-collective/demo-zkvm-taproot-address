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

fn sha256(data: &[u8]) -> [u8; 32] {
    use risc0_zkvm::sha;
    use sha::Sha256;
    sha::Impl::hash_bytes(&data).as_bytes().try_into().unwrap()
}

pub fn derive_address_zkvm(raw_private_address: Vec<u8>) -> String {
    let pvt: [u8; 32] = raw_private_address.try_into().unwrap();
    let private_key = libsecp256k1::SecretKey::parse_slice(&pvt).unwrap();
    let public_key = libsecp256k1::PublicKey::from_secret_key(&private_key);

    // bdk uses the secp256k1 lib using c-bindings. Since that doesn't compile at the moment
    // for zkVM, we use the libsecp256k1 library written in pure Rust. However, unlike the
    // C-bindings, this library does not contain X-only math functions. As such, we first
    // convert the pubkey into the X-only equivalent, by fixing the sign-byte and re-parsing
    // the result.
    let mut xonly_pubkey_compressed = public_key.serialize_compressed();
    xonly_pubkey_compressed[0] = 0x02; //bip 340: "our X-only public keys become equivalent to a compressed public key that is the X-only key prefixed by the byte 0x02."
    let mut x_only_public_key = libsecp256k1::PublicKey::parse_slice(&xonly_pubkey_compressed, None).unwrap();

    // The compressed key is the sign byte, followed by the x-coordinate. Extract only
    // the latter part
    let x_coord: [u8; 32] = xonly_pubkey_compressed[1..].try_into().unwrap();

    // The contents of the final taproot address is not the public key directly, but rather
    // transformed ("tweaked") version of it. See bip341.
    // Calculate the tweak.
    let h1 = sha256(b"TapTweak");
    let h2 = sha256(b"TapTweak");
    let tweak = sha256(&[&h1[..], &h2[..], &x_coord[..]].concat());

    // apply the tweak
    let tweak_as_secret = libsecp256k1::SecretKey::parse_slice(&tweak).unwrap();
    x_only_public_key.tweak_add_assign(&tweak_as_secret).unwrap();
    let tweaked_pubkey = x_only_public_key.serialize_compressed();

    // The compressed key is the sign byte, followed by the x-coordinate. Extract only
    // the latter part
    let tweaked_x_coordinate = &tweaked_pubkey[1..];
    // convert the resulting public key into bech32m
    use bech32::segwit;
    let taproot_address =
        segwit::encode(bech32::hrp::BCRT, segwit::VERSION_1, &tweaked_x_coordinate)
            .expect("valid witness version and program");

    taproot_address
}
