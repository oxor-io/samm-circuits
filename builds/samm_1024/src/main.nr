use dep::zkemail::{
    KEY_LIMBS_1024, dkim::verify_dkim_1024
};
use dep::samm::{
    LEVELS, MAX_EMAIL_HEADER_LENGTH, MAX_EMAIL_ADDRESS_LENGTH,
    MSG_HASH_LENGTH, verify_samm_logic
};


fn main(
    header: [u8; MAX_EMAIL_HEADER_LENGTH],
    header_length: u32,
    root: pub Field,
    path_indices: [Field; LEVELS],
    path_elements: [Field; LEVELS],
    padded_member: [u8; MAX_EMAIL_ADDRESS_LENGTH],
    member_length: u32,
    padded_relayer: pub [u8; MAX_EMAIL_ADDRESS_LENGTH],
    relayer_length: pub u32,
    msg_hash: pub [u8; MSG_HASH_LENGTH],
    pubkey_modulus_limbs: pub [Field; KEY_LIMBS_1024],
    redc_params_limbs: pub [Field; KEY_LIMBS_1024],
    signature: [Field; KEY_LIMBS_1024]
) -> pub Field {
    // check samm logic
    let commitment = verify_samm_logic(header, header_length, root, path_indices, path_elements, padded_member,
        member_length, padded_relayer, relayer_length, msg_hash);

    // check DKIM signature
    verify_dkim_1024(header, header_length, pubkey_modulus_limbs, redc_params_limbs, signature);
    
    commitment
}
