mod merkle_tree;
mod utils;
mod signature;

use merkle_tree::compute_merkle_root;

use dep::rsa::bignum::BigNum;
use dep::rsa::bignum::fields::Params2048;

global RSA_EXPONENT: u32 = 65537;
global KEY_BYTES_2048: u32 = 256;
global KEY_LIMBS_2048: u32 = 18;
type BN2048 = BigNum<KEY_LIMBS_2048, Params2048>;

global LEVELS: Field = 8; // Depth of the tree
global EMAIL_HEADER_LENGTH: u32 = 530; // TODO make parameter
global MAX_EMAIL_ADDRESS_LENGTH: u32 = 64; // the max length of email address
global MSG_HASH_LENGTH: u32 = 44; // base64 hash

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
    pubkey_modulus_limbs: [Field; KEY_LIMBS_2048],
    redc_params_limbs: [Field; KEY_LIMBS_2048],
    signature: BN2048
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
}

#[test]
fn test_samm() {
    let header: [u8; EMAIL_HEADER_LENGTH] = [
        116, 111, 58, 97, 100, 64, 111, 120, 111, 114, 46, 105, 111, 13, 10, 102, 114, 111, 109, 58, 115, 119, 111, 111, 110, 115, 46, 48, 48, 114, 117, 98, 98, 105, 110, 103, 64, 105, 99, 108, 111, 117, 100, 46, 99, 111, 109, 13, 10, 115, 117, 98, 106, 101, 99, 116, 58, 119, 70, 50, 115, 90, 68, 120, 52, 109, 99, 75, 54, 65, 115, 74, 88, 84, 74, 77, 82, 103, 83, 111, 99, 115, 67, 112, 50, 50, 87, 87, 102, 90, 119, 120, 120, 119, 82, 72, 106, 103, 112, 48, 61, 13, 10, 100, 97, 116, 101, 58, 87, 101, 100, 44, 32, 57, 32, 79, 99, 116, 32, 50, 48, 50, 52, 32, 49, 50, 58, 51, 51, 58, 51, 48, 32, 43, 48, 48, 48, 48, 32, 40, 85, 84, 67, 41, 13, 10, 109, 101, 115, 115, 97, 103, 101, 45, 105, 100, 58, 60, 70, 57, 53, 50, 67, 70, 49, 65, 45, 54, 48, 51, 51, 45, 52, 53, 53, 66, 45, 65, 50, 56, 67, 45, 69, 53, 51, 53, 65, 70, 70, 65, 68, 48, 48, 68, 64, 105, 99, 108, 111, 117, 100, 46, 99, 111, 109, 62, 13, 10, 99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101, 58, 109, 117, 108, 116, 105, 112, 97, 114, 116, 47, 97, 108, 116, 101, 114, 110, 97, 116, 105, 118, 101, 59, 32, 98, 111, 117, 110, 100, 97, 114, 121, 61, 65, 112, 112, 108, 101, 45, 87, 101, 98, 109, 97, 105, 108, 45, 52, 50, 45, 45, 98, 97, 56, 56, 54, 100, 51, 51, 45, 50, 98, 99, 56, 45, 52, 97, 102, 52, 45, 57, 99, 51, 49, 45, 54, 99, 52, 56, 101, 49, 51, 54, 101, 99, 50, 102, 13, 10, 109, 105, 109, 101, 45, 118, 101, 114, 115, 105, 111, 110, 58, 49, 46, 48, 13, 10, 100, 107, 105, 109, 45, 115, 105, 103, 110, 97, 116, 117, 114, 101, 58, 118, 61, 49, 59, 32, 97, 61, 114, 115, 97, 45, 115, 104, 97, 50, 53, 54, 59, 32, 99, 61, 114, 101, 108, 97, 120, 101, 100, 47, 114, 101, 108, 97, 120, 101, 100, 59, 32, 100, 61, 105, 99, 108, 111, 117, 100, 46, 99, 111, 109, 59, 32, 115, 61, 49, 97, 49, 104, 97, 105, 59, 32, 116, 61, 49, 55, 50, 56, 52, 55, 55, 50, 49, 51, 59, 32, 98, 104, 61, 105, 116, 84, 86, 66, 71, 57, 67, 49, 52, 90, 85, 47, 43, 97, 51, 72, 68, 69, 77, 90, 114, 71, 79, 52, 118, 73, 79, 48, 80, 99, 87, 110, 81, 72, 106, 77, 101, 100, 107, 108, 67, 69, 61, 59, 32, 104, 61, 84, 111, 58, 70, 114, 111, 109, 58, 83, 117, 98, 106, 101, 99, 116, 58, 68, 97, 116, 101, 58, 77, 101, 115, 115, 97, 103, 101, 45, 73, 100, 58, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 58, 77, 73, 77, 69, 45, 86, 101, 114, 115, 105, 111, 110, 59, 32, 98, 61
    ];

    // tree part 
    let leaf = 13780856135824609486835123660791248959181113742546918549559321242116770234576;
    let path_indices = [0,0,1,1,0,1,1,0];
    let path_elements = [14520510218039433773459597944105601781578483631006408988284677481489650471896,16735405162150476769165535806199980191266151907719469609340290185602038249334,11607634630385916762103142687024023731847490136503700052557112073181947753651,1094530894963466396181348105151045704221228209480186211832907007839607915796,3284044843315180235425920080565507273212761221150458610158014968492963231945,4641050443441813769099735638332230934538706616831662404912867311564816535000,13308983921089595976695015024214414181663897095192147251475586735720084500210,12699940109500066053124654505808015855541980379149317240855603319465855478536];
    let root = 3507270469832926990571112645872386345557614009066375654691910206440851534809;

    // member
    let member = "swoons.00rubbing@icloud.com".as_bytes();
    let mut padded_member: [u8; MAX_EMAIL_ADDRESS_LENGTH] = [0; MAX_EMAIL_ADDRESS_LENGTH];
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
    let relayer = "ad@oxor.io".as_bytes();
    let mut padded_relayer: [u8; MAX_EMAIL_ADDRESS_LENGTH] = [0; MAX_EMAIL_ADDRESS_LENGTH];
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
    let subject = "wF2sZDx4mcK6AsJXTJMRgSocsCp22WWfZwxxwRHjgp0=".as_bytes();
    let mut msg_hash: [u8; MSG_HASH_LENGTH] = [0; MSG_HASH_LENGTH];
    for i in 0..subject.len() {
        msg_hash[i] = subject[i];
    }

    println("MSG_HASH ---");
    println(msg_hash);

    // signature part
    let signature: BN2048 = BigNum::from_array(
        [
            0x036499d81b4b11cbd6faadf6316686, 0x43a7331b0ae6a7759942e7016d6b18, 0xa7d924f656955590882016ec93dc34, 0xb585fc6cc1c13e3401d600942d2ffb, 0x3a3729aeef5cb98d99b213c580783a, 0xfc31ed86eedd12dcf6531145168789, 0x17206b0f5f1dfcfe86fa51bac607e7, 0x7bfd0bad81f70680e83c6e6c37e749, 0x1ff3ec298c99698c4740da86683906, 0x397ea7ac5b04f44c7b3f02abdce5f1, 0x79a45ca602dcd89c1bb4425e805a2b, 0xc0336211a7661e839aeaa149506576, 0x07bb835ed40db4470b58a7cbb24c45, 0x0c07f73f4609f4d0b8a589895c8a80, 0xf7bdee9cfed9017610ed7d705bb134, 0xd2d4e46f35361ea5ececb77d41e454, 0x2f87b397e8050a6cf7d778b173e536, 0x38
        ]
    );
    let pubkey_modulus_limbs: [Field; 18] = [
        0xe5cf995b5ef59ce9943d1f4209b6ab, 0xe0caf03235e91a2db27e9ed214bcc6, 0xafe1309f87414bd36ed296dacfade2, 0xbeff3f19046a43adce46c932514988, 0x324041af8736e87de4358860fff057, 0xadcc6669dfa346f322717851a8c22a, 0x8b2a193089e6bf951c553b5a6f71aa, 0x0a570fe582918c4f731a0002068df2, 0x39419a433d6bfdd1978356cbca4b60, 0x550d695a514d38b45c862320a00ea5, 0x1c56ac1dfbf1beea31e8a613c2a51f, 0x6a30c9f22d2e5cb6934263d0838809, 0x0a281f268a44b21a4f77a91a52f960, 0x5134dc3966c8e91402669a47cc8597, 0x71590781df114ec072e641cdc5d224, 0xa1bc0f0937489c806c1944fd029dc9, 0x911f6e47f84db3b64c3648ebb5a127, 0xd5
    ];
    let redc_params_limbs: [Field; 18] = [
        0xa48a824e4ebc7e0f1059f3ecfa57c4, 0x05c1db23f3c7d47ad7e7d7cfda5189, 0x79bb6bbbd8facf011f022fa9051aec, 0x24faa4cef474bed639362ea71f7a21, 0x1503aa50b77e24b030841a7d061581, 0x5bbf4e62805e1860a904c0f66a5fad, 0x5cbd24b72442d2ce647dd7d0a44368, 0x074a8839a4460c169dce7138efdaef, 0x0f06e09e3191b995b08e5b45182f65, 0x51fad4a89f8369fe10e5d4b6e149a1, 0xdc778b15982d11ebf7fe23b4e15f10, 0xa09ff3a4567077510c474e4ac0a21a, 0xb37e69e5dbb77167b73065e4c5ad6a, 0xecf4774e22e7fe3a38642186f7ae74, 0x16e72b5eb4c813a3b37998083aab81, 0xa48e7050aa8abedce5a45c16985376, 0xdd3285e53b322b221f7bcf4f8f8ad8, 0x0132
    ];


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
    );
}
