use bitcoincore_rpc::bitcoin::bip32::DerivationPath;
use bitcoincore_rpc::bitcoin::Address;
use bitcoincore_rpc::bitcoin::PrivateKey;
use bitcoincore_rpc::jsonrpc;
use ethers::abi::Token;
use ethers::types::H160;
use std::time::Duration;
pub const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(15);
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
use std::str::FromStr;
use ethers::{abi::ethabi, types::Address as EthAddress};
use bonsai_ethereum_relay::sdk::client::{CallbackRequest, Client as BonsaiClient};
use risc0_zkvm::sha::Digest;
use methods::TAPROOT_ID;
use clap::Parser;

fn connect_bitcoin_rpc() -> Client {
    let transport = jsonrpc::simple_http::Builder::new()
        .url("http://localhost:18443/wallet/ord")
        .unwrap()
        .timeout(TRANSPORT_TIMEOUT)
        .auth("rpcuser", Some("rpcpassword"))
        .build();
    //
    //
    let rpc_client = jsonrpc::Client::with_transport(transport);
    Client::from_jsonrpc(rpc_client)
}

fn dump_private_key(client: Client, address: &Address) -> Option<PrivateKey> {
    // there is no easy way to dump private keys of descriptor wallets in bitcoin core.
    // We resort to listing all descriptors, and testing which one corresponds to our address 
    let result = client.list_descriptors(true).unwrap();

    for descriptor in result.descriptors {
        let range = descriptor
            .range
            .map(|[start, end]| [start, end.max(descriptor.next.unwrap_or(end))]);

        // One descriptor can derive multiple address, loop over all
        for (idx, generated_address) in client.derive_addresses(&descriptor.desc, range).unwrap().into_iter().enumerate() {
            if address == &generated_address.assume_checked() {
                println!("Found private address!");

                // extract the extended private key and the derivation path
                let re =
                    regex::Regex::new(r"tr\((\[.*\])?([tx]prv[a-zA-Z0-9]+)(.*)?\)").expect("Regex is known good");
                if let Some(caps) = re.captures(&descriptor.desc) {
                    let xprv = &caps[2];
                    println!("private key = {xprv}");

                    let key = bitcoincore_rpc::bitcoin::bip32::ExtendedPrivKey::from_str(xprv).unwrap();
                    let secp = bitcoincore_rpc::bitcoin::key::Secp256k1::new();

                    // found the extended private key corresponding to the address, now combine the
                    // extended key and the derivation path (if any) into a single, non-extended key
                    let private_key = if let Some(x) = caps.get(3) {
                        let idx = idx + range.map(|x| x[0] as usize).unwrap_or_default();

                        let mut path = x.as_str().to_string(); 
                        path = path.replace("*", &format!("{idx}"));
                        println!("Derivation path: {}", path);

                        let derivation_path = DerivationPath::from_str(&format!("m{path}")).unwrap();
                        key.derive_priv(&secp, &derivation_path).unwrap()
                    } else {
                        key
                    }.to_priv();
                    
                    return Some(private_key);
                }
            }
        }
    }

    None
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let h = sha256::digest(data);
    hex::decode(h).unwrap().try_into().unwrap()
}

fn derive_address_zkvm(raw_private_address: Vec<u8>) -> String {
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

async fn sumbit_to_bonsai(app_address: &str, bonsai_api_key: &str, raw_eth_address: &str, private_key: PrivateKey) {
    let eth_address:[u8; 20] = hex::decode(raw_eth_address).unwrap().try_into().unwrap();
    let address = Token::Address(EthAddress::from_slice(&eth_address));
    let private_key = Token::Bytes(private_key.to_bytes());
    let input = ethabi::encode(&[address, private_key]);

    let relay_client = BonsaiClient::from_parts(
        "http://localhost:8080".to_string(),
        bonsai_api_key.to_string(), 
    )
    .expect("Failed to initialize the relay client");

    let request = CallbackRequest {
        callback_contract: H160::from_str(app_address).unwrap(),
        function_selector: [0x1e, 0xcb, 0x53, 0xea], // proveOwnership(address,string)
        gas_limit: 3000000,
        image_id: Digest::from(TAPROOT_ID).into(),
        input,
    };

    relay_client
        .callback_request(request)
        .await
        .expect("Bonsai callback request failed");
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about)]
struct Args {
    /// Who to allow use of this taproot address.
    #[arg(long)]
    address: String,

    /// Taproot address to prove ownership of.
    #[arg(long)]
    taproot_address: String,

    /// Bonsai API key. 
    #[arg(long)]
    bonsai_api_key: String,

    #[arg(long)]
    taproot_derive_address: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    
    let bitcoin_rpc = connect_bitcoin_rpc();

    let address = Address::from_str(&args.taproot_address).unwrap().assume_checked();

    println!("Fetching private key...");
    let private_key = dump_private_key(bitcoin_rpc, &address).unwrap();

    // sanity check that our logic is correct. 
    println!("Checking derivation logic...");
    let derived_address = derive_address_zkvm(private_key.clone().to_bytes());
    assert_eq!(derived_address, args.taproot_address);

    println!("Submitting to Bonsai for proving...");

    sumbit_to_bonsai(&args.taproot_derive_address, &args.bonsai_api_key, &args.address, private_key).await;

    println!("Done.");
}
