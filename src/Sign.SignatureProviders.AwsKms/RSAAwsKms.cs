// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using System.Security.Cryptography;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;

namespace Sign.SignatureProviders.AwsKms
{
    /// <summary>
    /// RSA implementation that delegates signing operations to AWS KMS.
    /// </summary>
    internal sealed class RSAAwsKms : RSA
    {
        private readonly IAmazonKeyManagementService _kmsClient;
        private readonly string _keyId;
        private readonly RSA _rsaPublicKey;

        public RSAAwsKms(IAmazonKeyManagementService kmsClient, string keyId, RSA rsaPublicKey)
        {
            ArgumentNullException.ThrowIfNull(kmsClient, nameof(kmsClient));
            ArgumentException.ThrowIfNullOrEmpty(keyId, nameof(keyId));
            ArgumentNullException.ThrowIfNull(rsaPublicKey, nameof(rsaPublicKey));

            _kmsClient = kmsClient;
            _keyId = keyId;
            _rsaPublicKey = rsaPublicKey;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _rsaPublicKey.Dispose();
            }

            base.Dispose(disposing);
        }

        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            if (includePrivateParameters)
            {
                throw new NotSupportedException("Private key export is not supported for AWS KMS keys.");
            }

            return _rsaPublicKey.ExportParameters(false);
        }

        public override void ImportParameters(RSAParameters parameters)
            => throw new NotImplementedException("Importing parameters is not supported for AWS KMS keys.");

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            ArgumentNullException.ThrowIfNull(hash, nameof(hash));
            ArgumentNullException.ThrowIfNull(padding, nameof(padding));

            if (padding != RSASignaturePadding.Pkcs1)
            {
                throw new NotSupportedException($"Only PKCS#1 v1.5 padding is supported. Requested: {padding}");
            }

            string signingAlgorithm = GetKmsSigningAlgorithm(hashAlgorithm);

            SignRequest request = new()
            {
                KeyId = _keyId,
                Message = new MemoryStream(hash),
                MessageType = MessageType.DIGEST,
                SigningAlgorithm = signingAlgorithm
            };

            // Use synchronous call via GetAwaiter().GetResult() since RSA.SignHash is synchronous
            SignResponse response = _kmsClient.SignAsync(request).GetAwaiter().GetResult();

            return response.Signature.ToArray();
        }

        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            => _rsaPublicKey.VerifyHash(hash, signature, hashAlgorithm, padding);

        private static string GetKmsSigningAlgorithm(HashAlgorithmName hashAlgorithm)
        {
            if (hashAlgorithm == HashAlgorithmName.SHA256)
            {
                return SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256;
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA384)
            {
                return SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384;
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA512)
            {
                return SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512;
            }
            else
            {
                throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Name}' is not supported by AWS KMS.");
            }
        }
    }
}

