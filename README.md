This demo shows how to connect to external centralized (Amazon s3) and decentralized (Arweave through 4everland) storage services using Phala Fat Contract’s HTTP request capabilities. This satisfies many general usages, where Phala provides the computing power and any storage services with a RESTful API provides the data storage.

After setting up your [s3](https://aws.amazon.com/s3/)  or [4everland](https://www.4everland.org/bucket/)  bucket and sealing your API credentials, you can reference the demo to perform simple GET and PUT operations.

### Details
1. The demo safely seals the API credentials in the contract storage, thanks to the privacy-protecting Phala Blockchain that encrypts transactions and states by default.
2. For both s3 and 4eveland (s3-API-compatible), the AWS4 signature added to the authorization header in the HTTP request is manually calculated. You can check the [general signing process](https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html) and the [specific signing requirements](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html) for s3. 
> **_NOTE:_** Although a [Rust SDK for aws](https://github.com/awslabs/aws-sdk-rust) is in development , the ink! contract does not support the `async` functions that most API SDKs use in awaiting HTTP responses.
3. The demo encrypts and decrypts the data to be stored before uploading and downloading from the storage service, using RustCrypto’s AEAD crate. You can customize the process (e.g. algorithm, choice of key/nonce) by referencing here (https://github.com/RustCrypto/AEADs). 


### Performance

Since the GET and PUT logic is written in a Query (a function that does not alter the contract storage with an immutable reference in the function parameter), their execution is sent to a Phala Secure Worker using the secure enclave. 

This means the HTTP request is made in a fully-functional off-chain execution environment. As such, its performance is the same as any client-server programs.

- Maximum object size for a single PUT operation: 5GB
- Maximum object size for a multi-part PUT operation: 5TB
- Maximum object size for a single GET operation: 5TB

For details of other API action limits, you can check for [s3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/upload-objects.html) and for [4everland](https://docs.4everland.org/bucket-api/#limits-of-s3-api).
