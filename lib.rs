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
    // use scale::{Decode, Encode};

    use pink::{http_get, PinkEnvironment};

    // To generate AWS4 Signature
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use sha2::Digest;

    // To format block timestamp for http request headers
    use chrono::{TimeZone, Utc};

    // Wrap PUT request in macro
    macro_rules! http_put {
        ($url: expr, $data: expr, $headers: expr) => {{
            use pink::chain_extension::{HttpRequest, HttpResponse};
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
        access_key_id: String,
        secret_key: String
    }

    impl FatContractS3Sync {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                access_key_id: "Not Initialized".to_string(),
                secret_key: "Not Initialized".to_string()
            }
        }

        #[ink(message)]
        pub fn seal_credentials(&mut self, access_key_id: String, secret_key: String) -> () {
            self.access_key_id = access_key_id;
            self.secret_key = secret_key;
        }

        pub fn get_time(&self) -> (String, String) {

            // Get block time (UNIX time in nano seconds)and convert to Utc datetime object
            let time = self.env().block_timestamp()/1000;
            let datetime = Utc.timestamp(time.try_into().unwrap(), 0);
            debug_println!("time: {}\ndatetime: {}\n", time, datetime);

            // Format both date and datetime per request
            let datestamp = datetime.format("%Y%m%d").to_string();
            let datetimestamp = datetime.format("%Y%m%dT%H%M%SZ").to_string();

            debug_println!("datestamp: {}\ndatetimestamp: {}\n", &datestamp, &datetimestamp);
            (datestamp, datetimestamp)
        }

        #[ink(message)]
        pub fn get_object(&self, object_key: String, bucket_name: String) -> String {
            // https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html

            // Set request values
            let method = "GET";
            let service = "s3";
            let host = format!("{}.s3.amazonaws.com", bucket_name);
            let region = "ap-southeast-1";
            let payload_hash = format!("{:x}", Sha256::digest(b""));

            // Get current time: datestamp (20220727) and amz_date (20220727T141618Z)
            let (datestamp, amz_date) = self.get_time();

            // 1. Create canonical request
            let canonical_uri = format!("/{}", object_key);
            let canonical_querystring = "";
            let canonical_headers = format!("host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
                                            host,
                                            payload_hash,
                                            amz_date);
            let signed_headers = "host;x-amz-content-sha256;x-amz-date";
            let canonical_request = format!("{}\n{}\n{}\n{}\n{}\n{}",
                                        method,
                                        canonical_uri,
                                        canonical_querystring,
                                        canonical_headers,
                                        signed_headers,
                                        payload_hash);

            debug_println!(" -- Canonical request -- \n{}\n", canonical_request);

            // 2. Create string to sign
            let algorithm = "AWS4-HMAC-SHA256";
            let credential_scope = format!("{}/{}/{}/aws4_request",
                                           datestamp,
                                           region,
                                           service);
            let canonical_request_hash = format!("{:x}", Sha256::digest(&canonical_request.as_bytes()));
            let string_to_sign = format!("{}\n{}\n{}\n{}",
                                         algorithm,
                                         amz_date,
                                         credential_scope,
                                         canonical_request_hash);

            debug_println!(" -- String to sign -- \n{}\n", string_to_sign);

            // 3. Calculate signature
            let signature_key = get_signature_key(
                self.secret_key.as_bytes(),
                &datestamp.as_bytes(),
                &region.as_bytes(),
                &service.as_bytes());
            let mut signature_hasher = HmacSha256::new_from_slice(&signature_key)
                .expect("Could not instantiate HMAC instance for signature");
            signature_hasher.update(&string_to_sign.as_bytes());
            let signature = format!("{:x}", signature_hasher.finalize().into_bytes());

            debug_println!(" -- Signature -- \n{}\n", &signature);

            // 4. Create authorization header
            let authorization_header = format!("{} Credential={}/{},SignedHeaders={},Signature={}",
                                               algorithm,
                                               self.access_key_id,
                                               credential_scope,
                                               signed_headers,
                                               signature);

            let headers: Vec<(String, String)> = vec![
                ("Host".into(), host.to_string()),
                ("Authorization".into(), authorization_header.clone()),
                ("x-amz-content-sha256".into(), payload_hash),
                ("x-amz-date".into(), amz_date)];

            let request_url = format!("https://{}.s3.{}.amazonaws.com/{}", bucket_name, region, object_key);
            debug_println!(" -- HTTP Request -- \nUrl: {}\n Headers: {:?}\n", &request_url, &headers);

            let response = http_get!(request_url, headers);
            debug_println!(" -- HTTP Response -- \nStatus code: {}", response.status_code);

            let result = String::from_utf8_lossy(&response.body);
            debug_println!("Response body: {}", result);
            result.to_string()
        }

        #[ink(message)]
        pub fn put_object(&self, object_key: String, bucket_name: String, comment: String) -> String {
            // https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html

            // Set request values
            let method = "PUT";
            let service = "s3";
            let host = format!("{}.s3.amazonaws.com", bucket_name);
            let region = "ap-southeast-1";
            let payload_hash = format!("{:x}", Sha256::digest(comment.as_bytes()));
            let content_length = format!("{}", comment.clone().into_bytes().len());

            // Get datestamp (20220727) and amz_date (20220727T141618Z)
            let (datestamp, amz_date) = self.get_time();

            // 1. Create canonical request
            let canonical_uri = format!("/{}", object_key);
            let canonical_querystring = "";
            let canonical_headers = format!("host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
                                            host,
                                            payload_hash,
                                            amz_date);
            let signed_headers = "host;x-amz-content-sha256;x-amz-date";
            let canonical_request = format!("{}\n{}\n{}\n{}\n{}\n{}",
                                        method,
                                        canonical_uri,
                                        canonical_querystring,
                                        canonical_headers,
                                        signed_headers,
                                        payload_hash);

            debug_println!(" -- Canonical request -- \n{}\n", canonical_request);

            // 2. Create string to sign
            let algorithm = "AWS4-HMAC-SHA256";
            let credential_scope = format!("{}/{}/{}/aws4_request",
                                           datestamp,
                                           region,
                                           service);
            let canonical_request_hash = format!("{:x}", Sha256::digest(&canonical_request.as_bytes()));
            let string_to_sign = format!("{}\n{}\n{}\n{}",
                                         algorithm,
                                         amz_date,
                                         credential_scope,
                                         canonical_request_hash);

            debug_println!(" -- String to sign -- \n{}\n", string_to_sign);

            // 3. Calculate signature
            let signature_key = get_signature_key(
                self.secret_key.as_bytes(),
                &datestamp.as_bytes(),
                &region.as_bytes(),
                &service.as_bytes());
            let mut signature_hasher = HmacSha256::new_from_slice(&signature_key)
                .expect("Could not instantiate HMAC instance for signature");
            signature_hasher.update(&string_to_sign.as_bytes());
            let signature = format!("{:x}", signature_hasher.finalize().into_bytes());

            debug_println!(" -- Signature -- \n{}\n", &signature);

            // 4. Create authorization header
            let authorization_header = format!("{} Credential={}/{},SignedHeaders={},Signature={}",
                                               algorithm,
                                               self.access_key_id,
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

            let request_url = format!("https://{}.s3.{}.amazonaws.com/{}", bucket_name, region, object_key);
            debug_println!(" -- HTTP Request -- \nHeaders: {:?}\nURL: {}\n", headers.clone(), request_url);

            let response = http_put!(request_url, comment, headers);
            debug_println!(" -- HTTP Response -- \nStatus code: {}", response.status_code);
            debug_println!("Response body: {:?}", String::from_utf8_lossy(&response.body));

            format!("{}\n{}\n{:?}\n{:?}", response.status_code, response.reason_phrase, response.headers, response.body)
        }
    }
    // Create alias for HMAC-SHA256
    type HmacSha256 = Hmac<Sha256>;

    // Returns encrypted hex bytes of key and message using SHA256
    pub fn sign (key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("Could not instantiate HMAC instance");
        mac.update(msg);
        let result = mac.finalize().into_bytes().to_vec();
        result
    }

    // Returns the signature key for the complicated version
    pub fn get_signature_key(key: &[u8], datestamp: &[u8], region_name: &[u8], service_name: &[u8]) -> Vec<u8> {
        let k_date = sign(&[b"AWS4", key].concat(), datestamp);
        let k_region = sign(&k_date, region_name);
        let k_service = sign(&k_region, service_name);
        let k_signing = sign(&k_service, b"aws4_request");
        return k_signing
    }

    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// Imports `ink_lang` so we can use `#[ink::test]`.
        use ink_lang as ink;

        #[ink::test]
        fn put_object_works() {
            use pink_extension::chain_extension::{mock, HttpResponse};

            mock::mock_http_request(|request| {
                if request.url == "https://fat-contract-s3-sync.s3.ap-southeast-1.amazonaws.com/test/api-upload" {
                    HttpResponse::ok(b"success".to_vec())
                } else {
                    HttpResponse::not_found()
                }
            });

            let mut contract = FatContractS3Sync::new();
            contract.seal_credentials("<AWS Access Key ID>".to_string(), "<AWS Secret Key>".to_string());
            let response = contract.put_object("test/api-upload".to_string(), "fat-contract-s3-sync".to_string(), "phala ui".to_string());
            assert_eq!(response, "200\nOK\n[]\n[115, 117, 99, 99, 101, 115, 115]");
        }
    }
}
