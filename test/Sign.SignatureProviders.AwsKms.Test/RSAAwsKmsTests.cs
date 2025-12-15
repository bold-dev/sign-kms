// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using System.Security.Cryptography;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Moq;
using Moq.Protected;

namespace Sign.SignatureProviders.AwsKms.Test
{
    public class RSAAwsKmsTests
    {
        private readonly Mock<IAmazonKeyManagementService> _kmsClient = new();
        private readonly Mock<RSA> _rsaPublicKey = new();
        private const string TestKeyId = "test-key-id";

        [Fact]
        public void Constructor_WhenKmsClientIsNull_Throws()
        {
            ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
                () => new RSAAwsKms(kmsClient: null!, TestKeyId, _rsaPublicKey.Object));

            Assert.Equal("kmsClient", exception.ParamName);
        }

        [Fact]
        public void Constructor_WhenKeyIdIsNull_Throws()
        {
            ArgumentException exception = Assert.Throws<ArgumentNullException>(
                () => new RSAAwsKms(_kmsClient.Object, keyId: null!, _rsaPublicKey.Object));

            Assert.Equal("keyId", exception.ParamName);
        }

        [Fact]
        public void Constructor_WhenKeyIdIsEmpty_Throws()
        {
            ArgumentException exception = Assert.Throws<ArgumentException>(
                () => new RSAAwsKms(_kmsClient.Object, keyId: "", _rsaPublicKey.Object));

            Assert.Equal("keyId", exception.ParamName);
        }

        [Fact]
        public void Constructor_WhenRsaPublicKeyIsNull_Throws()
        {
            ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
                () => new RSAAwsKms(_kmsClient.Object, TestKeyId, rsaPublicKey: null!));

            Assert.Equal("rsaPublicKey", exception.ParamName);
        }

        [Fact]
        public void Dispose_DisposesRSAPublicKey()
        {
            RSAAwsKms rsaAwsKms = new(_kmsClient.Object, TestKeyId, _rsaPublicKey.Object);
            rsaAwsKms.Dispose();

            _rsaPublicKey.Protected().Verify(nameof(RSA.Dispose), Times.Once(), [true]);
        }

        [Fact]
        public void ExportParameters_IncludePrivateParametersIsTrue_Throws()
        {
            using RSAAwsKms rsaAwsKms = new(_kmsClient.Object, TestKeyId, _rsaPublicKey.Object);

            Assert.Throws<NotSupportedException>(
                () => rsaAwsKms.ExportParameters(true));
        }

        [Fact]
        public void ExportParameters_IncludePrivateParametersIsFalse_UsesExportParametersOfPublicKey()
        {
            using RSAAwsKms rsaAwsKms = new(_kmsClient.Object, TestKeyId, _rsaPublicKey.Object);

            rsaAwsKms.ExportParameters(false);

            _rsaPublicKey.Verify(_ => _.ExportParameters(false), Times.Once());
        }

        [Fact]
        public void ImportParameters_Throws()
        {
            using RSAAwsKms rsaAwsKms = new(_kmsClient.Object, TestKeyId, _rsaPublicKey.Object);

            Assert.Throws<NotImplementedException>(
                () => rsaAwsKms.ImportParameters(default));
        }

        [Fact]
        public void SignHash_WhenPaddingIsNotPkcs1_Throws()
        {
            using RSAAwsKms rsaAwsKms = new(_kmsClient.Object, TestKeyId, _rsaPublicKey.Object);

            byte[] hash = new byte[32];
            HashAlgorithmName hashAlgorithmName = HashAlgorithmName.SHA256;
            RSASignaturePadding padding = RSASignaturePadding.Pss;

            Assert.Throws<NotSupportedException>(
                () => rsaAwsKms.SignHash(hash, hashAlgorithmName, padding));
        }

        [Fact]
        public void SignHash_WhenHashAlgorithmIsNotSupported_Throws()
        {
            using RSAAwsKms rsaAwsKms = new(_kmsClient.Object, TestKeyId, _rsaPublicKey.Object);

            byte[] hash = new byte[16];
            HashAlgorithmName hashAlgorithmName = HashAlgorithmName.MD5;
            RSASignaturePadding padding = RSASignaturePadding.Pkcs1;

            Assert.Throws<NotSupportedException>(
                () => rsaAwsKms.SignHash(hash, hashAlgorithmName, padding));
        }

        [Fact]
        public void SignHash_CallsKmsSignAsync()
        {
            byte[] expectedSignature = new byte[] { 1, 2, 3, 4 };
            SignResponse signResponse = new()
            {
                Signature = new MemoryStream(expectedSignature)
            };

            _kmsClient
                .Setup(x => x.SignAsync(It.IsAny<SignRequest>(), default))
                .ReturnsAsync(signResponse);

            using RSAAwsKms rsaAwsKms = new(_kmsClient.Object, TestKeyId, _rsaPublicKey.Object);

            byte[] hash = new byte[32];
            HashAlgorithmName hashAlgorithmName = HashAlgorithmName.SHA256;
            RSASignaturePadding padding = RSASignaturePadding.Pkcs1;

            byte[] signature = rsaAwsKms.SignHash(hash, hashAlgorithmName, padding);

            Assert.Equal(expectedSignature, signature);
            _kmsClient.Verify(x => x.SignAsync(
                It.Is<SignRequest>(r =>
                    r.KeyId == TestKeyId &&
                    r.MessageType == MessageType.DIGEST &&
                    r.SigningAlgorithm == SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256),
                default), Times.Once());
        }

        [Fact]
        public void VerifyHash_UsesPublicKey()
        {
            using RSAAwsKms rsaAwsKms = new(_kmsClient.Object, TestKeyId, _rsaPublicKey.Object);

            byte[] hash = [];
            byte[] signature = [];
            HashAlgorithmName hashAlgorithmName = HashAlgorithmName.SHA256;
            RSASignaturePadding padding = RSASignaturePadding.Pkcs1;

            rsaAwsKms.VerifyHash(hash, signature, hashAlgorithmName, padding);

            _rsaPublicKey.Verify(_ => _.VerifyHash(hash, signature, hashAlgorithmName, padding), Times.Once());
        }
    }
}

