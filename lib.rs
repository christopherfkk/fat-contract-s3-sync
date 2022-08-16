#![cfg_attr(not(feature = "std"), no_std)]

// use ink_lang as ink;
use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod fat_contract_s3_sync {

    use super::pink;
    use ink_prelude::{string::{String, ToString}, vec::Vec};
    use ink_prelude::vec;
    use ink_prelude::format;
    use ink_env;
    use ink_env::debug_println;
    use scale::{Decode, Encode};

    // To make HTTP request
    use pink::{http_get, PinkEnvironment};

    // To generate AWS4 Signature
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use sha2::Digest;

    // To format block timestamp for http request headers
    use chrono::{TimeZone, Utc};

    // To encrypt/decrypt HTTP payloads
    use aes_gcm_siv::aead::{Aead, KeyInit, Nonce};
    use aes_gcm_siv::Aes256GcmSiv;
    use pink::chain_extension::signing;
    use cipher::{consts::{U12, U32}, generic_array::GenericArray};
    use base16;

    // Wrap PUT request in macro
    macro_rules! http_put {
        ($url: expr, $data: expr, $headers: expr) => {{
            use pink::chain_extension::HttpRequest;
            let headers = $headers;
            let body = $data.into();
            let request = HttpRequest {
                url: $url.into(),
                method: "PUT".into(),
                headers,
                body,
            };
            pink::ext().http_request(request)
        }};
        ($url: expr, $data: expr) => {{
            pink::http_put!($url, $data, Default::default())
        }};
    }

    // Make macro available for use inside/outside of module
    pub(crate) use http_put;

    #[ink(storage)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct FatContractS3Sync {
        access_key_aws: String,
        secret_key_aws: String,
        access_key_4everland: String,
        secret_key_4everland: String,
    }

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        RequestFailed,
        EncryptionFailed,
        DecryptionFailed
    }

    impl FatContractS3Sync {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                access_key_aws: "Not Sealed".to_string(),
                secret_key_aws: "Not Sealed".to_string(),
                access_key_4everland: "Not Sealed".to_string(),
                secret_key_4everland: "Not Sealed".to_string(),
            }
        }

        #[ink(message)]
        pub fn seal_aws_credentials(&mut self, access_key_aws: String, secret_key_aws: String) -> () {
            self.access_key_aws = access_key_aws;
            self.secret_key_aws = secret_key_aws;
        }

        pub fn get_time(&self) -> (String, String) {

            // Get block time (UNIX time in nano seconds)and convert to Utc datetime object
            let time = self.env().block_timestamp()/1000;
            let datetime = Utc.timestamp(time.try_into().unwrap(), 0);

            // Format both date and datetime for AWS4 signature
            let datestamp = datetime.format("%Y%m%d").to_string();
            let datetimestamp = datetime.format("%Y%m%dT%H%M%SZ").to_string();

            (datestamp, datetimestamp)
        }

        #[ink(message)]
        pub fn get_s3_object(&self, object_key: String, bucket_name: String, region: String) -> Result<String, Error> {

            // Set request values
            let method = "GET";
            let service = "s3";
            let host = format!("{}.s3.amazonaws.com", bucket_name);
            let payload_hash = format!("{:x}", Sha256::digest(b"")); // GET has default payload empty byte

            // Get current time: datestamp (e.g. 20220727) and amz_date (e.g. 20220727T141618Z)
            let (datestamp, amz_date) = self.get_time();

            // 1. Create canonical request
            let canonical_uri = format!("/{}", object_key);
            let canonical_querystring = "";
            let canonical_headers = format!("host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n", host, payload_hash, amz_date);
            let signed_headers = "host;x-amz-content-sha256;x-amz-date";
            let canonical_request = format!("{}\n{}\n{}\n{}\n{}\n{}",
                                        method,
                                        canonical_uri,
                                        canonical_querystring,
                                        canonical_headers,
                                        signed_headers,
                                        payload_hash);

            debug_println!(" ----- Canonical request -----  \n{}\n", canonical_request);
            //  ----- Canonical request -----
            // GET
            // /test/api-upload
            //
            // host:fat-contract-s3-sync.s3.amazonaws.com
            // x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            // x-amz-date:19700101T000000Z
            //
            // host;x-amz-content-sha256;x-amz-date
            // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

            // 2. Create "String to sign"
            let algorithm = "AWS4-HMAC-SHA256";
            let credential_scope = format!("{}/{}/{}/aws4_request", datestamp, region, service);
            let canonical_request_hash = format!("{:x}", Sha256::digest(&canonical_request.as_bytes()));
            let string_to_sign = format!("{}\n{}\n{}\n{}",
                                         algorithm,
                                         amz_date,
                                         credential_scope,
                                         canonical_request_hash);

            debug_println!(" ----- String to sign ----- \n{}\n", string_to_sign);
            //  ----- String to sign -----
            // AWS4-HMAC-SHA256
            // 19700101T000000Z
            // 19700101/ap-southeast-1/s3/aws4_request
            // ec70fa653b4f867cda7a59007db15a7e95ed45d70bacdfb55902a2fb09b6367f

            // 3. Calculate signature
            let signature_key = get_signature_key(
                self.secret_key_aws.as_bytes(),
                &datestamp.as_bytes(),
                &region.as_bytes(),
                &service.as_bytes());
            let signature_bytes = hmac_sign(&signature_key, &string_to_sign.as_bytes());
            let signature = format!("{}", base16::encode_lower(&signature_bytes));

            debug_println!(" ----- Signature ----- \n{}\n", &signature);
            //  ----- Signature -----
            // 485e174a7fed1691de34f116a968981709ed5a00f4975470bd3d0dd06ccd3e1d

            // 4. Create authorization header
            let authorization_header = format!("{} Credential={}/{}, SignedHeaders={}, Signature={}",
                                               algorithm,
                                               self.access_key_aws,
                                               credential_scope,
                                               signed_headers,
                                               signature);

            debug_println!(" ----- Authorization header ----- \nAuthorization: {}\n", &authorization_header);
            //  ----- Authorization header -----
            // Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/19700101/ap-southeast-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=485e174a7fed1691de34f116a968981709ed5a00f4975470bd3d0dd06ccd3e1d

            let headers: Vec<(String, String)> = vec![
                ("Host".into(), host.to_string()),
                ("Authorization".into(), authorization_header.clone()),
                ("x-amz-content-sha256".into(), payload_hash),
                ("x-amz-date".into(), amz_date)];

            // Make HTTP GET request
            let request_url = format!("https://{}.s3.{}.amazonaws.com/{}", bucket_name, region, object_key);
            let response = http_get!(request_url, headers);

            if response.status_code != 200 {
                return Err(Error::RequestFailed);
            }

            // Generate key and nonce
            let key_bytes: Vec<u8> = signing::derive_sr25519_key(object_key.as_bytes())[..32].to_vec();
            let key: &GenericArray<u8, U32> = GenericArray::from_slice(&key_bytes);
            let nonce_bytes: Vec<u8> = vec![0; 12];
            let nonce: &GenericArray<u8, U12> = Nonce::<Aes256GcmSiv>::from_slice(&nonce_bytes);

            // Decrypt payload
            let cipher = Aes256GcmSiv::new(key.into());
            let plaintext = cipher.decrypt(&nonce, response.body.as_ref()).or(Err(Error::DecryptionFailed));
            let result = format!("{}", String::from_utf8_lossy(&plaintext.unwrap()));

            Ok(result)
        }

        #[ink(message)]
        pub fn put_s3_object(&self, object_key: String, bucket_name: String, region: String, payload: String) -> Result<(), Error> {

            // Generate key and nonce
            let key_bytes: Vec<u8> = signing::derive_sr25519_key(object_key.as_bytes())[..32].to_vec();
            let key: &GenericArray<u8, U32> = GenericArray::from_slice(&key_bytes);
            let nonce_bytes: Vec<u8> = self.access_key_4everland.as_bytes()[..12].to_vec();
            let nonce: &GenericArray<u8, U12> = Nonce::<Aes256GcmSiv>::from_slice(&nonce_bytes);

            // Encrypt payload
            let cipher = Aes256GcmSiv::new(key.into());
            let ciphertext: Vec<u8> = cipher.encrypt(nonce, payload.as_bytes().as_ref()).unwrap();

            // Set request values
            let method = "PUT";
            let service = "s3";
            let host = format!("{}.s3.amazonaws.com", bucket_name);
            let payload_hash = format!("{:x}", Sha256::digest(&ciphertext));
            let content_length = format!("{}", ciphertext.clone().len());

            // Get datestamp (20220727) and amz_date (20220727T141618Z)
            let (datestamp, amz_date) = self.get_time();

            // 1. Create canonical request
            let canonical_uri = format!("/{}", object_key);
            let canonical_querystring = "";
            let canonical_headers = format!("host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n", host, payload_hash, amz_date);
            let signed_headers = "host;x-amz-content-sha256;x-amz-date";
            let canonical_request = format!("{}\n{}\n{}\n{}\n{}\n{}",
                                        method,
                                        canonical_uri,
                                        canonical_querystring,
                                        canonical_headers,
                                        signed_headers,
                                        payload_hash);

            debug_println!(" ----- Canonical request -----  \n{}\n", canonical_request);
            //  ----- Canonical request -----
            // PUT
            // /test/api-upload
            //
            // host:fat-contract-s3-sync.s3.amazonaws.com
            // x-amz-content-sha256:505f2ec6d688d6e15f718b5c91edd07c45310e08e8c221018a7c0f103515fa28
            // x-amz-date:19700101T000000Z
            //
            // host;x-amz-content-sha256;x-amz-date
            // 505f2ec6d688d6e15f718b5c91edd07c45310e08e8c221018a7c0f103515fa28

            // 2. Create string to sign
            let algorithm = "AWS4-HMAC-SHA256";
            let credential_scope = format!("{}/{}/{}/aws4_request", datestamp, region, service);
            let canonical_request_hash = format!("{:x}", Sha256::digest(&canonical_request.as_bytes()));
            let string_to_sign = format!("{}\n{}\n{}\n{}",
                                         algorithm,
                                         amz_date,
                                         credential_scope,
                                         canonical_request_hash);

            debug_println!(" ----- String to sign ----- \n{}\n", string_to_sign);
            //  ----- String to sign -----
            // AWS4-HMAC-SHA256
            // 19700101T000000Z
            // 19700101/ap-southeast-1/s3/aws4_request
            // efd07a6d8013f3c35d4c3d6b7f52f86ae682c51a8639fe80b8f68198107e3039

            // 3. Calculate signature
            let signature_key = get_signature_key(
                self.secret_key_aws.as_bytes(),
                &datestamp.as_bytes(),
                &region.as_bytes(),
                &service.as_bytes());
            let signature_bytes = hmac_sign(&signature_key, &string_to_sign.as_bytes());
            let signature = format!("{}", base16::encode_lower(&signature_bytes));

            debug_println!(" ----- Signature ----- \n{}\n", &signature);
            //  ----- Signature -----
            // 84bf2db9f7a0007f5124cf2e9c0e1b7e1cec2b1b1b209ab9458387caa3b8da52

            // 4. Create authorization header
            let authorization_header = format!("{} Credential={}/{},SignedHeaders={},Signature={}",
                                               algorithm,
                                               self.access_key_aws,
                                               credential_scope,
                                               signed_headers,
                                               signature);

            debug_println!(" ----- Authorization header ----- \nAuthorization: {}\n", &authorization_header);
            //  ----- Authorization header -----
            // Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/19700101/ap-southeast-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=b9b6bcb29b1369678e3a3cfae411a5277c084c8c1796bb6e78407f402f9e3f3d

            let headers: Vec<(String, String)> = vec![
                ("Host".into(), host.to_string()),
                ("Authorization".into(), authorization_header),
                ("Content-Length".into(), content_length),
                ("Content-Type".into(), "binary/octet-stream".into()),
                ("x-amz-content-sha256".into(), payload_hash),
                ("x-amz-date".into(), amz_date)];

            let request_url = format!("https://{}.s3.{}.amazonaws.com/{}", bucket_name, region, object_key);
            let response = http_put!(request_url, payload, headers);

            if response.status_code != 200 {
                return Err(Error::RequestFailed);
            }

            Ok(())
        }

        #[ink(message)]
        pub fn seal_4everland_credentials(&mut self, access_key_4everland: String, secret_key_4everland: String) -> () {
            self.access_key_4everland = access_key_4everland;
            self.secret_key_4everland = secret_key_4everland;
        }

        #[ink(message)]
        pub fn get_4everland_object(&self, object_key: String, bucket_name: String) -> Result<String, Error> {

            // Set request values
            let method = "GET";
            let service = "s3";
            let region = "us-east-1"; // default for 4everland
            let host = "endpoint.4everland.co"; // bucket name not included unlike s3
            let payload_hash = format!("{:x}", Sha256::digest(b"")); // GET has default payload empty byte

            // Get current time: datestamp (e.g. 20220727) and amz_date (e.g. 20220727T141618Z)
            let (datestamp, amz_date) = self.get_time();

            // 1. Create canonical request
            let canonical_uri = format!("/{}/{}", bucket_name, object_key); // bucket name included unlike s3
            let canonical_querystring = "";
            let canonical_headers = format!("host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n", host, payload_hash, amz_date);
            let signed_headers = "host;x-amz-content-sha256;x-amz-date";
            let canonical_request = format!("{}\n{}\n{}\n{}\n{}\n{}",
                                        method,
                                        canonical_uri,
                                        canonical_querystring,
                                        canonical_headers,
                                        signed_headers,
                                        payload_hash);

            // 2. Create "String to sign"
            let algorithm = "AWS4-HMAC-SHA256";
            let credential_scope = format!("{}/{}/{}/aws4_request", datestamp, region, service);
            let canonical_request_hash = format!("{:x}", Sha256::digest(&canonical_request.as_bytes()));
            let string_to_sign = format!("{}\n{}\n{}\n{}",
                                         algorithm,
                                         amz_date,
                                         credential_scope,
                                         canonical_request_hash);

            // 3. Calculate signature
            let signature_key = get_signature_key(
                self.secret_key_4everland.as_bytes(),
                &datestamp.as_bytes(),
                &region.as_bytes(),
                &service.as_bytes());
            let signature_bytes = hmac_sign(&signature_key, &string_to_sign.as_bytes());
            let signature = format!("{}", base16::encode_lower(&signature_bytes));

            // 4. Create authorization header
            let authorization_header = format!("{} Credential={}/{}, SignedHeaders={}, Signature={}",
                                               algorithm,
                                               self.access_key_4everland,
                                               credential_scope,
                                               signed_headers,
                                               signature);

            let headers: Vec<(String, String)> = vec![
                ("Host".into(), host.to_string()),
                ("Authorization".into(), authorization_header.clone()),
                ("x-amz-content-sha256".into(), payload_hash),
                ("x-amz-date".into(), amz_date)];

            // Make HTTP GET request
            let request_url = format!("https://endpoint.4everland.co/{}/{}", bucket_name, object_key);
            let response = http_get!(request_url, headers);

            if response.status_code != 200 {
                return Err(Error::RequestFailed);
            }

            // Generate key and nonce
            let key_bytes: Vec<u8> = signing::derive_sr25519_key(object_key.as_bytes())[..32].to_vec();
            let key: &GenericArray<u8, U32> = GenericArray::from_slice(&key_bytes);
            let nonce_bytes: Vec<u8> = self.access_key_4everland.as_bytes()[..12].to_vec();
            let nonce: &GenericArray<u8, U12> = Nonce::<Aes256GcmSiv>::from_slice(&nonce_bytes);

            // Decrypt payload
            let cipher = Aes256GcmSiv::new(key.into());
            let decrypted_bytes: Result<Vec<u8>, Error> = cipher.decrypt(&nonce, response.body.as_ref())
                .or(Err(Error::DecryptionFailed));
            let result = format!("{}", String::from_utf8_lossy(&decrypted_bytes.unwrap()));

            Ok(result)
        }

        #[ink(message)]
        pub fn put_4everland_object(&self, object_key: String, bucket_name: String, payload: String) -> Result<(), Error> {

            // Generate key and nonce
            let key_bytes: Vec<u8> = signing::derive_sr25519_key(object_key.as_bytes())[..32].to_vec();
            let key: &GenericArray<u8, U32> = GenericArray::from_slice(&key_bytes);
            let nonce_bytes: Vec<u8> = self.access_key_4everland.as_bytes()[..12].to_vec();
            let nonce: &GenericArray<u8, U12> = Nonce::<Aes256GcmSiv>::from_slice(&nonce_bytes);

            // Encrypt payload
            let cipher = Aes256GcmSiv::new(key.into());
            let encrypted_bytes: Vec<u8> = cipher.encrypt(nonce, payload.as_bytes().as_ref()).unwrap();

            // Set request values
            let method = "PUT";
            let service = "s3";
            let region = "us-east-1"; // default for 4everland
            let host = "endpoint.4everland.co"; // bucket name not included unlike s3
            let payload_hash = format!("{:x}", Sha256::digest(&encrypted_bytes));
            let content_length = format!("{}", &encrypted_bytes.len());

            // Get current time: datestamp (e.g. 20220727) and amz_date (e.g. 20220727T141618Z)
            let (datestamp, amz_date) = self.get_time();

            // 1. Create canonical request
            let canonical_uri = format!("/{}/{}", bucket_name, object_key); // bucket name included unlike s3
            let canonical_querystring = "";
            let canonical_headers = format!("host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n", host, payload_hash, amz_date);
            let signed_headers = "host;x-amz-content-sha256;x-amz-date";
            let canonical_request = format!("{}\n{}\n{}\n{}\n{}\n{}",
                                        method,
                                        canonical_uri,
                                        canonical_querystring,
                                        canonical_headers,
                                        signed_headers,
                                        payload_hash);

            // 2. Create "String to sign"
            let algorithm = "AWS4-HMAC-SHA256";
            let credential_scope = format!("{}/{}/{}/aws4_request", datestamp, region, service);
            let canonical_request_hash = format!("{:x}", Sha256::digest(&canonical_request.as_bytes()));
            let string_to_sign = format!("{}\n{}\n{}\n{}",
                                         algorithm,
                                         amz_date,
                                         credential_scope,
                                         canonical_request_hash);

            // 3. Calculate signature
            let signature_key = get_signature_key(
                self.secret_key_4everland.as_bytes(),
                &datestamp.as_bytes(),
                &region.as_bytes(),
                &service.as_bytes());
            let signature_bytes = hmac_sign(&signature_key, &string_to_sign.as_bytes());
            let signature = format!("{}", base16::encode_lower(&signature_bytes));

            // 4. Create authorization header
            let authorization_header = format!("{} Credential={}/{}, SignedHeaders={}, Signature={}",
                                               algorithm,
                                               self.access_key_4everland,
                                               credential_scope,
                                               signed_headers,
                                               signature);

            let headers: Vec<(String, String)> = vec![
                ("Host".into(), host.to_string()),
                ("Authorization".into(), authorization_header),
                ("Content-Length".into(), content_length),
                ("Content-Type".into(), "binary/octet-stream".into()),
                ("x-amz-content-sha256".into(), payload_hash),
                ("x-amz-date".into(), amz_date)];

            // Make HTTP PUT request
            let request_url = format!("https://endpoint.4everland.co/{}/{}", bucket_name, object_key);
            let response = http_put!(request_url, encrypted_bytes, headers);

            if response.status_code != 200 {
                return Err(Error::RequestFailed);
            }

            Ok(())
        }
    }

    // Create alias for HMAC-SHA256
    type HmacSha256 = Hmac<Sha256>;

    // Returns encrypted hex bytes of key and message using SHA256
    pub fn hmac_sign (key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("Could not instantiate HMAC instance");
        mac.update(msg);
        let result = mac.finalize().into_bytes();
        result.to_vec()
    }

    // Returns the signature key for the complicated version
    pub fn get_signature_key(key: &[u8], datestamp: &[u8], region_name: &[u8], service_name: &[u8]) -> Vec<u8> {
        let k_date = hmac_sign(&[b"AWS4", key].concat(), datestamp);
        let k_region = hmac_sign(&k_date, region_name);
        let k_service = hmac_sign(&k_region, service_name);
        let k_signing = hmac_sign(&k_service, b"aws4_request");
        return k_signing
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;

        // #[ink::test]
        // fn put_s3_object_works() {
        //     pink_extension_runtime::mock_ext::mock_all_ext();
        //
        //     let mut contract = FatContractS3Sync::new();
        //     contract.seal_aws_credentials("AKIAIOSFODNN7EXAMPLE".to_string(), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string());
        //     let response = contract.put_s3_object(
        //         "test/api-upload".to_string(),
        //         "fat-contract-s3-sync".to_string(),
        //         "ap-southeast-1".to_string(),
        //         "This is a test comment".to_string());
        //     debug_println!("{:?}", response);
        //     // assert_eq!(response, "200\nOK\nSuccess");
        //     assert!(false)
        // }

        // #[ink::test]
        // fn put_4everland_object_works() {
        //     use pink_extension::chain_extension::{mock, HttpResponse};
        //
        //     mock::mock_http_request(|request| {
        //         if request.url == "https://endpoint.4everland.co/fat-contract-4everland-sync/test/api-upload" {
        //             HttpResponse::ok(b"Success".to_vec())
        //         } else {
        //             HttpResponse::not_found()
        //         }
        //     });
        //
        //     let mut contract = FatContractS3Sync::new();
        //     contract.seal_4everland_credentials("AKIAIOSFODNN7EXAMPLE".to_string(), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string());
        //     let response = contract.put_4everland_object(
        //         "test/api-upload".to_string(),
        //         "fat-contract-4everland-sync".to_string(),
        //         "This is a test comment".to_string());
        //     assert_eq!(response, "200\nOK\nSuccess");
        // }

        #[ink::test]
        fn aead_works() {

            let payload = "test";

            // Generate key and nonce
            let key_bytes: Vec<u8> = vec![0; 32];
            let key: &GenericArray<u8, U32> = GenericArray::from_slice(&key_bytes);
            let nonce_bytes: Vec<u8> = vec![0; 12];
            let nonce: &GenericArray<u8, U12> = Nonce::<Aes256GcmSiv>::from_slice(&nonce_bytes);

            // Encrypt payload
            let cipher = Aes256GcmSiv::new(key.into());
            let encrypted_text: Vec<u8> = cipher.encrypt(nonce, payload.as_bytes().as_ref()).unwrap();

            // Generate key and nonce
            let key_bytes: Vec<u8> = vec![0; 32];
            let key: &GenericArray<u8, U32> = GenericArray::from_slice(&key_bytes);
            let nonce_bytes: Vec<u8> = vec![0; 12];
            let nonce: &GenericArray<u8, U12> = Nonce::<Aes256GcmSiv>::from_slice(&nonce_bytes);

            // Decrypt payload
            let cipher = Aes256GcmSiv::new(key.into());
            let decrypted_text = cipher.decrypt(&nonce, encrypted_text.as_ref()).unwrap();

            assert_eq!(payload.as_bytes(), decrypted_text);
            assert_eq!(payload, String::from_utf8_lossy(&decrypted_text));
        }
    }
}