use crate::{EMAIL_HEADER_LENGTH, MAX_EMAIL_ADDRESS_LENGTH, MSG_HASH_LENGTH, CREATION_DATA_LENGTH};
use dep::string_search::{StringBody, SubString, StringBody512, SubString32, SubString64};

/**
 * Attempt to find "from" field in the email header
 *
 * @param header - the entire email header to search through
 * @param padded_from - the sender email address
 * @param from_length - the length of the sender email address
 * @returns (true/false if found, index of start in the header)
 */
pub fn find_from_in_header(
    header: [u8; EMAIL_HEADER_LENGTH],
    padded_from: [u8; MAX_EMAIL_ADDRESS_LENGTH],
    from_length: u32
) -> (bool, u32) {
    // init the search params
    let needle_text_init: [u8; 5] = "from:".as_bytes();
    let needle_start: SubString32 = SubString::new(needle_text_init, needle_text_init.len());
    let needle_end: SubString64 = SubString::new(padded_from, from_length);
    let needle = needle_start.concat_into(needle_end);

    // init the search domain
    let haystack: StringBody512 = StringBody::new(header, EMAIL_HEADER_LENGTH);

    // find the index of the position
    haystack.substring_match(needle)
}

/**
 * Attempt to find "to" field in the email header
 *
 * @param header - the entire email header to search through
 * @param padded_to - the recipient email address
 * @param to_length - the length of the recipient email address
 * @returns (true/false if found, index of start in the header)
 */
pub fn find_to_in_header(
    header: [u8; EMAIL_HEADER_LENGTH],
    padded_to: [u8; MAX_EMAIL_ADDRESS_LENGTH],
    to_length: u32
) -> (bool, u32) {
    // init the search params
    let needle_text_init: [u8; 3] = "to:".as_bytes();
    let needle_start: SubString32 = SubString::new(needle_text_init, needle_text_init.len());
    let needle_end: SubString64 = SubString::new(padded_to, to_length);
    let needle = needle_start.concat_into(needle_end);

    // init the search domain
    let haystack: StringBody512 = StringBody::new(header, EMAIL_HEADER_LENGTH);

    // find the index of the position
    haystack.substring_match(needle)
}

/**
 * Attempt to find "subject" field in the email header
 *
 * @param header - the entire email header to search through
 * @param subject - the subject of email address
 * @returns (true/false if found, index of start in the header)
 */
pub fn find_subject_in_header(
    header: [u8; EMAIL_HEADER_LENGTH],
    subject: [u8; MSG_HASH_LENGTH]
) -> (bool, u32) {
    // init the search params
    let needle_text_init: [u8; 8] = "subject:".as_bytes();
    let needle_start: SubString32 = SubString::new(needle_text_init, needle_text_init.len());
    let needle_end: SubString64 = SubString::new(subject, subject.len());
    let needle = needle_start.concat_into(needle_end);

    // init the search domain
    let haystack: StringBody512 = StringBody::new(header, EMAIL_HEADER_LENGTH);

    // find the index of the position
    haystack.substring_match(needle)
}

/**
 * Attempt to find "date" field in the email header
 *
 * @param header - the entire email header to search through
 * @param date - the date of email address
 * @returns (true/false if found, index of start in the header)
 */
pub fn find_date_in_header(
    header: [u8; EMAIL_HEADER_LENGTH],
    date: [u8; CREATION_DATA_LENGTH]
) -> (bool, u32) {
    // init the search params
    let needle_text_init: [u8; 5] = "date:".as_bytes();
    let needle_start: SubString32 = SubString::new(needle_text_init, needle_text_init.len());
    let needle_end: SubString64 = SubString::new(date, date.len());
    let needle = needle_start.concat_into(needle_end);

    // init the search domain
    let haystack: StringBody512 = StringBody::new(header, EMAIL_HEADER_LENGTH);

    // find the index of the position
    haystack.substring_match(needle)
}

#[test]
fn test_find_to_in_header() {
    // make padded username
    let username = "zkewtest".as_bytes();
    let mut padded_username: [u8; 64] = [0; 64];
    for i in 0..username.len() {
        padded_username[i] = username[i];
    }
    for i in username.len()..MAX_EMAIL_ADDRESS_LENGTH {
        padded_username[i] = 0;
    }

    let header: [u8; EMAIL_HEADER_LENGTH] = [
        102, 114, 111, 109, 58, 114, 117, 110, 110, 105, 101, 114, 46, 108, 101, 97, 103, 117, 101, 115, 46, 48, 106, 64, 105, 99, 108, 111, 117, 100, 46, 99, 111, 109, 13, 10, 99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101, 58, 116, 101, 120, 116, 47, 112, 108, 97, 105, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 115, 45, 97, 115, 99, 105, 105, 13, 10, 109, 105, 109, 101, 45, 118, 101, 114, 115, 105, 111, 110, 58, 49, 46, 48, 32, 40, 77, 97, 99, 32, 79, 83, 32, 88, 32, 77, 97, 105, 108, 32, 49, 54, 46, 48, 32, 92, 40, 51, 55, 51, 49, 46, 53, 48, 48, 46, 50, 51, 49, 92, 41, 41, 13, 10, 115, 117, 98, 106, 101, 99, 116, 58, 72, 101, 108, 108, 111, 13, 10, 109, 101, 115, 115, 97, 103, 101, 45, 105, 100, 58, 60, 56, 70, 56, 49, 57, 68, 51, 50, 45, 66, 54, 65, 67, 45, 52, 56, 57, 68, 45, 57, 55, 55, 70, 45, 52, 51, 56, 66, 66, 67, 52, 67, 65, 66, 50, 55, 64, 109, 101, 46, 99, 111, 109, 62, 13, 10, 100, 97, 116, 101, 58, 83, 97, 116, 44, 32, 50, 54, 32, 65, 117, 103, 32, 50, 48, 50, 51, 32, 49, 50, 58, 50, 53, 58, 50, 50, 32, 43, 48, 52, 48, 48, 13, 10, 116, 111, 58, 122, 107, 101, 119, 116, 101, 115, 116, 64, 103, 109, 97, 105, 108, 46, 99, 111, 109, 13, 10, 100, 107, 105, 109, 45, 115, 105, 103, 110, 97, 116, 117, 114, 101, 58, 118, 61, 49, 59, 32, 97, 61, 114, 115, 97, 45, 115, 104, 97, 50, 53, 54, 59, 32, 99, 61, 114, 101, 108, 97, 120, 101, 100, 47, 114, 101, 108, 97, 120, 101, 100, 59, 32, 100, 61, 105, 99, 108, 111, 117, 100, 46, 99, 111, 109, 59, 32, 115, 61, 49, 97, 49, 104, 97, 105, 59, 32, 116, 61, 49, 54, 57, 51, 48, 51, 56, 51, 51, 55, 59, 32, 98, 104, 61, 55, 120, 81, 77, 68, 117, 111, 86, 86, 85, 52, 109, 48, 87, 48, 87, 82, 86, 83, 114, 86, 88, 77, 101, 71, 83, 73, 65, 83, 115, 110, 117, 99, 75, 57, 100, 74, 115, 114, 99, 43, 118, 85, 61, 59, 32, 104, 61, 102, 114, 111, 109, 58, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 58, 77, 105, 109, 101, 45, 86, 101, 114, 115, 105, 111, 110, 58, 83, 117, 98, 106, 101, 99, 116, 58, 77, 101, 115, 115, 97, 103, 101, 45, 73, 100, 58, 68, 97, 116, 101, 58, 116, 111, 59, 32, 98, 61
    ];

    let (found, _) = find_to_in_header(header, padded_username, username.len());
    assert(found);
}