This demo shows how to connect Phala's Fat Contract to external storage services, both centralized (Amazon s3) and decentralized (Arweave/Filecoin through 4everland, Storj, Filebase).

### Background
In order to build Web3 programs, Phala Network provides the web3 computing power and any storage services (web2 or web3) with a RESTful API provides the data storage. To do this, we can use the native HTTP request support in Fat Contract to connect them. 

### Setup
The demo shows the `GET` and `PUT` request for the Amazon S3 API. The same authentication and request process can be applied to others like 4everland, Storj, and Filebase, since the S3 API is the industrial standard for storage interfaces.

You need to first create an account and set up a bucket on your selected storage interface, then obtain the S3 API credentials, i.e. 1) access key and 2) secret key, to seal in the contract. All interfaces have free tiers for trial.

A bucket is a container for data objects. For Amazon S3, you can have up to 100 buckets but can store any number objects in a bucket. The key of the object is unqiue within the bucket. For a more detailed overview, check [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingBucket.html)

> **_NOTE:_** For Amazon S3, you also need to select a region. Generally, a region closest to your location is preferred. For others, the default region should be set to be `us-east-1`.

- [Amazon S3](https://aws.amazon.com/s3/) - 5GB 12 months free
- [4everland](https://www.4everland.org/bucket/) - 5GB free on Filecoin IPFS and 100MB Free on Arweave
- [Storj](https://www.storj.io/) - 150GB free
- [Filebase](https://filebase.com/) - 5GB free

### Details
1. The demo safely seals the API credentials in the contract storage, thanks to the privacy-protecting Phala Blockchain that encrypts transactions and states by default.
2. For both s3 and 4eveland (s3-API-compatible), the AWS4 signature added to the authorization header in the HTTP request is manually calculated. You can check the [general signing process](https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html) and the [specific signing requirements](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html) for s3. 
> **_NOTE:_** Although a [Rust SDK for aws](https://github.com/awslabs/aws-sdk-rust) is in development , the ink! contract does not support the `async` functions that most API SDKs use in awaiting HTTP responses.
3. The demo encrypts and decrypts the data to be stored before uploading and downloading from the storage service, using RustCrypto’s AEAD crate. You can customize the process (e.g. algorithm, choice of key/nonce) by referencing [here](https://github.com/RustCrypto/AEADs). 


### Performance

Since the GET and PUT logic is written in a Query (a function that does not alter the contract storage with an immutable reference in the function parameter), their execution is sent to a Phala Secure Worker using the secure enclave. 

This means the HTTP request is made in a fully-functional off-chain execution environment. As such, its performance is the same as any client-server programs.

- Maximum object size for a single PUT operation: 5GB
- Maximum object size for a multi-part PUT operation: 5TB
- Maximum object size for a single GET operation: 5TB

For details of other API action limits, you can check for [s3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/upload-objects.html) and for [4everland](https://docs.4everland.org/bucket-api/#limits-of-s3-api).
