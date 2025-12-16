// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using System.Security.Cryptography;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;

namespace Sign.SignatureProviders.AwsKms
{
    /// <summary>
    /// ECDsa implementation that delegates signing operations to AWS KMS.
    /// </summary>
    internal sealed class ECDsaAwsKms : ECDsa
    {
        private readonly IAmazonKeyManagementService _kmsClient;
        private readonly string _keyId;
        private readonly ECDsa _ecdsaPublicKey;
        private readonly int _keySize;

        public ECDsaAwsKms(IAmazonKeyManagementService kmsClient, string keyId, ECDsa ecdsaPublicKey)
        {
            ArgumentNullException.ThrowIfNull(kmsClient, nameof(kmsClient));
            ArgumentException.ThrowIfNullOrEmpty(keyId, nameof(keyId));
            ArgumentNullException.ThrowIfNull(ecdsaPublicKey, nameof(ecdsaPublicKey));

            _kmsClient = kmsClient;
            _keyId = keyId;
            _ecdsaPublicKey = ecdsaPublicKey;
            _keySize = ecdsaPublicKey.KeySize;
        }

        public override int KeySize
        {
            get => _keySize;
            set => throw new NotSupportedException("Cannot set key size for AWS KMS keys.");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _ecdsaPublicKey.Dispose();
            }

            base.Dispose(disposing);
        }

        public override ECParameters ExportParameters(bool includePrivateParameters)
        {
            if (includePrivateParameters)
            {
                throw new NotSupportedException("Private key export is not supported for AWS KMS keys.");
            }

            return _ecdsaPublicKey.ExportParameters(false);
        }

        public override ECParameters ExportExplicitParameters(bool includePrivateParameters)
        {
            if (includePrivateParameters)
            {
                throw new NotSupportedException("Private key export is not supported for AWS KMS keys.");
            }

            return _ecdsaPublicKey.ExportExplicitParameters(false);
        }

        public override void ImportParameters(ECParameters parameters)
            => throw new NotImplementedException("Importing parameters is not supported for AWS KMS keys.");

        public override void GenerateKey(ECCurve curve)
            => throw new NotSupportedException("Key generation is not supported for AWS KMS keys.");

        public override byte[] SignHash(byte[] hash)
        {
            ArgumentNullException.ThrowIfNull(hash, nameof(hash));

            string signingAlgorithm = GetKmsSigningAlgorithm(hash.Length);

            SignRequest request = new()
            {
                KeyId = _keyId,
                Message = new MemoryStream(hash),
                MessageType = MessageType.DIGEST,
                SigningAlgorithm = signingAlgorithm
            };

            // Use synchronous call via GetAwaiter().GetResult() since ECDsa.SignHash is synchronous
            SignResponse response = _kmsClient.SignAsync(request).GetAwaiter().GetResult();

            // AWS KMS returns DER-encoded signature, convert to IEEE P1363 format for .NET
            byte[] derSignature = response.Signature.ToArray();
            return ConvertDerToIeee(derSignature);
        }

        public override bool VerifyHash(byte[] hash, byte[] signature)
            => _ecdsaPublicKey.VerifyHash(hash, signature);

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            using HashAlgorithm hasher = hashAlgorithm.Name switch
            {
                "SHA256" => SHA256.Create(),
                "SHA384" => SHA384.Create(),
                "SHA512" => SHA512.Create(),
                _ => throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Name}' is not supported.")
            };

            return hasher.ComputeHash(data, offset, count);
        }

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            using HashAlgorithm hasher = hashAlgorithm.Name switch
            {
                "SHA256" => SHA256.Create(),
                "SHA384" => SHA384.Create(),
                "SHA512" => SHA512.Create(),
                _ => throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Name}' is not supported.")
            };

            return hasher.ComputeHash(data);
        }

        private string GetKmsSigningAlgorithm(int hashLength)
        {
            // Determine signing algorithm based on hash length and key size
            return hashLength switch
            {
                32 => SigningAlgorithmSpec.ECDSA_SHA_256, // SHA-256 produces 32 bytes
                48 => SigningAlgorithmSpec.ECDSA_SHA_384, // SHA-384 produces 48 bytes
                64 => SigningAlgorithmSpec.ECDSA_SHA_512, // SHA-512 produces 64 bytes
                _ => _keySize switch
                {
                    256 => SigningAlgorithmSpec.ECDSA_SHA_256,
                    384 => SigningAlgorithmSpec.ECDSA_SHA_384,
                    521 => SigningAlgorithmSpec.ECDSA_SHA_512,
                    _ => SigningAlgorithmSpec.ECDSA_SHA_256
                }
            };
        }

        /// <summary>
        /// Converts a DER-encoded ECDSA signature to IEEE P1363 format.
        /// AWS KMS returns DER format, but .NET expects IEEE P1363.
        /// </summary>
        private byte[] ConvertDerToIeee(byte[] derSignature)
        {
            // DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
            int offset = 2; // Skip 0x30 and total length

            if (derSignature[offset] != 0x02)
                throw new InvalidOperationException("Invalid DER signature format");

            offset++;
            int rLength = derSignature[offset++];
            byte[] r = new byte[rLength];
            Array.Copy(derSignature, offset, r, 0, rLength);
            offset += rLength;

            if (derSignature[offset] != 0x02)
                throw new InvalidOperationException("Invalid DER signature format");

            offset++;
            int sLength = derSignature[offset++];
            byte[] s = new byte[sLength];
            Array.Copy(derSignature, offset, s, 0, sLength);

            // Determine the coordinate size based on key size
            int coordinateSize = (_keySize + 7) / 8;
            if (_keySize == 521) coordinateSize = 66; // P-521 uses 66 bytes

            byte[] ieee = new byte[coordinateSize * 2];

            // Copy R (right-aligned, skip leading zeros if present)
            int rStart = r.Length > coordinateSize ? r.Length - coordinateSize : 0;
            int rDest = coordinateSize - (r.Length - rStart);
            Array.Copy(r, rStart, ieee, rDest, r.Length - rStart);

            // Copy S (right-aligned, skip leading zeros if present)
            int sStart = s.Length > coordinateSize ? s.Length - coordinateSize : 0;
            int sDest = coordinateSize + coordinateSize - (s.Length - sStart);
            Array.Copy(s, sStart, ieee, sDest, s.Length - sStart);

            return ieee;
        }
    }
}

