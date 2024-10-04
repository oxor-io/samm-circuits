mod merkle_tree;
mod utils;
mod signature;

use dep::std;
use merkle_tree::compute_merkle_root;

use dep::noir_rsa::bignum::BigNum;
use dep::noir_rsa::bignum::fields::Params2048;

type BN2048 = BigNum<18, Params2048>;

global LEVELS: Field = 8; // Depth of the tree
global EMAIL_HEADER_LENGTH: u32 = 472;
global MAX_EMAIL_ADDRESS_LENGTH: u32 = 64; // the max length of email address
global MSG_HASH_LENGTH: u32 = 5; // TODO change
global CREATION_DATA_LENGTH: u32 = 31;

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

#[test]
fn test_samm() {
    let header: [u8; EMAIL_HEADER_LENGTH] = [
        102, 114, 111, 109, 58, 114, 117, 110, 110, 105, 101, 114, 46, 108, 101, 97, 103, 117, 101, 115, 46, 48, 106, 64, 105, 99, 108, 111, 117, 100, 46, 99, 111, 109, 13, 10, 99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101, 58, 116, 101, 120, 116, 47, 112, 108, 97, 105, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 115, 45, 97, 115, 99, 105, 105, 13, 10, 109, 105, 109, 101, 45, 118, 101, 114, 115, 105, 111, 110, 58, 49, 46, 48, 32, 40, 77, 97, 99, 32, 79, 83, 32, 88, 32, 77, 97, 105, 108, 32, 49, 54, 46, 48, 32, 92, 40, 51, 55, 51, 49, 46, 53, 48, 48, 46, 50, 51, 49, 92, 41, 41, 13, 10, 115, 117, 98, 106, 101, 99, 116, 58, 72, 101, 108, 108, 111, 13, 10, 109, 101, 115, 115, 97, 103, 101, 45, 105, 100, 58, 60, 56, 70, 56, 49, 57, 68, 51, 50, 45, 66, 54, 65, 67, 45, 52, 56, 57, 68, 45, 57, 55, 55, 70, 45, 52, 51, 56, 66, 66, 67, 52, 67, 65, 66, 50, 55, 64, 109, 101, 46, 99, 111, 109, 62, 13, 10, 100, 97, 116, 101, 58, 83, 97, 116, 44, 32, 50, 54, 32, 65, 117, 103, 32, 50, 48, 50, 51, 32, 49, 50, 58, 50, 53, 58, 50, 50, 32, 43, 48, 52, 48, 48, 13, 10, 116, 111, 58, 122, 107, 101, 119, 116, 101, 115, 116, 64, 103, 109, 97, 105, 108, 46, 99, 111, 109, 13, 10, 100, 107, 105, 109, 45, 115, 105, 103, 110, 97, 116, 117, 114, 101, 58, 118, 61, 49, 59, 32, 97, 61, 114, 115, 97, 45, 115, 104, 97, 50, 53, 54, 59, 32, 99, 61, 114, 101, 108, 97, 120, 101, 100, 47, 114, 101, 108, 97, 120, 101, 100, 59, 32, 100, 61, 105, 99, 108, 111, 117, 100, 46, 99, 111, 109, 59, 32, 115, 61, 49, 97, 49, 104, 97, 105, 59, 32, 116, 61, 49, 54, 57, 51, 48, 51, 56, 51, 51, 55, 59, 32, 98, 104, 61, 55, 120, 81, 77, 68, 117, 111, 86, 86, 85, 52, 109, 48, 87, 48, 87, 82, 86, 83, 114, 86, 88, 77, 101, 71, 83, 73, 65, 83, 115, 110, 117, 99, 75, 57, 100, 74, 115, 114, 99, 43, 118, 85, 61, 59, 32, 104, 61, 102, 114, 111, 109, 58, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 58, 77, 105, 109, 101, 45, 86, 101, 114, 115, 105, 111, 110, 58, 83, 117, 98, 106, 101, 99, 116, 58, 77, 101, 115, 115, 97, 103, 101, 45, 73, 100, 58, 68, 97, 116, 101, 58, 116, 111, 59, 32, 98, 61
    ];

    // tree part 
    let leaf = 13780856135824609486835123660791248959181113742546918549559321242116770234576;
    let path_indices = [0,0,1,1,0,1,1,0];
    let path_elements = [14520510218039433773459597944105601781578483631006408988284677481489650471896,16735405162150476769165535806199980191266151907719469609340290185602038249334,11607634630385916762103142687024023731847490136503700052557112073181947753651,1094530894963466396181348105151045704221228209480186211832907007839607915796,3284044843315180235425920080565507273212761221150458610158014968492963231945,4641050443441813769099735638332230934538706616831662404912867311564816535000,13308983921089595976695015024214414181663897095192147251475586735720084500210,12699940109500066053124654505808015855541980379149317240855603319465855478536];
    let root = 3507270469832926990571112645872386345557614009066375654691910206440851534809;

    // member
    let member = "runnier.leagues.0j@icloud.com".as_bytes();
    let mut padded_member: [u8; 64] = [0; 64];
    for i in 0..member.len() {
        padded_member[i] = member[i];
    }
    for i in member.len()..MAX_EMAIL_ADDRESS_LENGTH {
        padded_member[i] = 0;
    }

    println("MEMBER ---");
    println(padded_member);
    println(member.len());

    // relayer
    let relayer = "zkewtest@gmail.com".as_bytes();
    let mut padded_relayer: [u8; 64] = [0; 64];
    for i in 0..relayer.len() {
        padded_relayer[i] = relayer[i];
    }
    for i in relayer.len()..MAX_EMAIL_ADDRESS_LENGTH {
        padded_relayer[i] = 0;
    }

    println("RELAYER ---");
    println(padded_relayer);
    println(relayer.len());

    // msg_hash
    let subject = "Hello".as_bytes();
    let mut msg_hash: [u8; MSG_HASH_LENGTH] = [0; MSG_HASH_LENGTH];
    for i in 0..subject.len() {
        msg_hash[i] = subject[i];
    }

    println("MSG_HASH ---");
    println(msg_hash);

    // signature part
    let signature: BN2048 = BigNum::from_array(
        [
        0x5779c85587e51cb8de5c29d7fdfeb0, 0xcd7ea8b6119f76f117ecb5042f8fc0, 0xeb7ac32b81d5a87bc2046fa0004e27, 0x62708c43b0c07a8fe8bdc97c479138, 0xc1e90d184f22a80be4a484a6ebd462, 0x39f3ff00e47728aaf74802d2d1d07b, 0x0f39de2cf99bf20dab7b8ae9240acd, 0xf4875cb76ce2538f255d70476136d6, 0xde151a5005ca614d6af7dd01e2a083, 0x6fe12b286f3195cae005fd7d2a1766, 0xd6e43a3060eccc555f2ee1e2929932, 0x0d5fa7cc79c794ae80310b491a1b40, 0x9cff415204cbc05c772ede05903440, 0xe7190ccff38575ae70dd055cd892d2, 0xf34bb777c0c842b0e88738eafdf634, 0x21040437e1e945a201ff58e542be68, 0x12f254fa4a0fb776ffe8759eb9eefa, 0x12
    ]
    );
    let pubkey_modulus_limbs: [Field; 18] = [
        0xe5cf995b5ef59ce9943d1f4209b6ab, 0xe0caf03235e91a2db27e9ed214bcc6, 0xafe1309f87414bd36ed296dacfade2, 0xbeff3f19046a43adce46c932514988, 0x324041af8736e87de4358860fff057, 0xadcc6669dfa346f322717851a8c22a, 0x8b2a193089e6bf951c553b5a6f71aa, 0x0a570fe582918c4f731a0002068df2, 0x39419a433d6bfdd1978356cbca4b60, 0x550d695a514d38b45c862320a00ea5, 0x1c56ac1dfbf1beea31e8a613c2a51f, 0x6a30c9f22d2e5cb6934263d0838809, 0x0a281f268a44b21a4f77a91a52f960, 0x5134dc3966c8e91402669a47cc8597, 0x71590781df114ec072e641cdc5d224, 0xa1bc0f0937489c806c1944fd029dc9, 0x911f6e47f84db3b64c3648ebb5a127, 0xd5
    ];
    let redc_params_limbs: [Field; 18] = [
        0xa48a824e4ebc7e0f1059f3ecfa57c4, 0x05c1db23f3c7d47ad7e7d7cfda5189, 0x79bb6bbbd8facf011f022fa9051aec, 0x24faa4cef474bed639362ea71f7a21, 0x1503aa50b77e24b030841a7d061581, 0x5bbf4e62805e1860a904c0f66a5fad, 0x5cbd24b72442d2ce647dd7d0a44368, 0x074a8839a4460c169dce7138efdaef, 0x0f06e09e3191b995b08e5b45182f65, 0x51fad4a89f8369fe10e5d4b6e149a1, 0xdc778b15982d11ebf7fe23b4e15f10, 0xa09ff3a4567077510c474e4ac0a21a, 0xb37e69e5dbb77167b73065e4c5ad6a, 0xecf4774e22e7fe3a38642186f7ae74, 0x16e72b5eb4c813a3b37998083aab81, 0xa48e7050aa8abedce5a45c16985376, 0xdd3285e53b322b221f7bcf4f8f8ad8, 0x0132
    ];

    // data part
    let data = "Sat, 26 Aug 2023 12:25:22 +0400".as_bytes();
    let mut creation_data: [u8; CREATION_DATA_LENGTH] = [0; CREATION_DATA_LENGTH];
    for i in 0..data.len() {
        creation_data[i] = data[i];
    }

    println("DATA ---");
    println(creation_data);

    let creation_ts_limit: u64 = 1728035879;

    let _ = main(
        header,
        root,
        leaf,
        path_indices,
        path_elements,
        padded_member,
        member.len(),
        padded_relayer,
        relayer.len(),
        msg_hash,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature,
        creation_data,
        creation_ts_limit,
    );
}
