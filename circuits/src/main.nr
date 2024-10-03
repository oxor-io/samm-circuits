mod merkle_tree;
mod utils;
mod signature;

use dep::std;
use merkle_tree::compute_merkle_root;

use dep::noir_rsa::bignum::BigNum;
use dep::noir_rsa::bignum::fields::Params2048;

type BN2048 = BigNum<18, Params2048>;

global LEVELS: Field = 5; // Depth of the tree
global EMAIL_HEADER_LENGTH: u32 = 472;
global MAX_EMAIL_ADDRESS_LENGTH: u32 = 64; // the max length of email address
global MSG_HASH_LENGTH: u32 = 64;
global CREATION_DATA_LENGTH: u32 = 64;

fn main(
    header: [u8; EMAIL_HEADER_LENGTH],
    root: pub Field,
    leaf: Field,
    path_indices: [Field; LEVELS],
    path_elements: [Field; LEVELS],
    padded_member: pub [u8; MAX_EMAIL_ADDRESS_LENGTH],
    member_length: pub u32,
    padded_relayer: pub [u8; MAX_EMAIL_ADDRESS_LENGTH],
    relayer_length: pub u32,
    msg_hash: pub [u8; MSG_HASH_LENGTH],
    pubkey_modulus_limbs: [Field; 18],
    redc_params_limbs: [Field; 18],
    signature: BN2048,
    creation_data: [u8; CREATION_DATA_LENGTH],
    creation_ts_limit: pub u64
) {
    // sender must be member email address
    let (found, _) = utils::find_from_in_header(header, padded_member, member_length);
    assert(found);

    // check merkle inclusion proof of sender email
    let _root = compute_merkle_root(leaf, path_indices, path_elements);
    assert(_root == root);

    // recipient must be relayer email address
    let (found, _) = utils::find_to_in_header(header, padded_relayer, relayer_length);
    assert(found);

    // check that subject field of header is msgHash
    let (found, _) = utils::find_subject_in_header(header, msg_hash);
    assert(found);

    // check DKIM signature
    signature::check_DKIM_signature(header, pubkey_modulus_limbs, redc_params_limbs, signature);

    // check expiration of DKIM signature
    let (found, _) = utils::find_date_in_header(header, creation_data);
    assert(found);
    // TODO cast date to unix ts
    // let creation_ts = ...
    // assert(creation_ts >= creation_ts_limit);
}
