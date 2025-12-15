// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using Amazon.KeyManagementService;
using Microsoft.Extensions.Logging;
using Moq;
using Sign.TestInfrastructure;

namespace Sign.SignatureProviders.AwsKms.Test
{
    public class AwsKmsServiceTests
    {
        private readonly Mock<IAmazonKeyManagementService> _kmsClient = new();
        private readonly ILogger<AwsKmsService> _logger = new TestLogger<AwsKmsService>();
        private const string TestKeyId = "test-key-id";
        private const string TestCertificatePath = "/path/to/certificate.pem";

        [Fact]
        public void Constructor_WhenKmsClientIsNull_Throws()
        {
            ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
                () => new AwsKmsService(
                    kmsClient: null!,
                    TestKeyId,
                    TestCertificatePath,
                    _logger));

            Assert.Equal("kmsClient", exception.ParamName);
        }

        [Fact]
        public void Constructor_WhenKeyIdIsNull_Throws()
        {
            ArgumentException exception = Assert.Throws<ArgumentNullException>(
                () => new AwsKmsService(
                    _kmsClient.Object,
                    keyId: null!,
                    TestCertificatePath,
                    _logger));

            Assert.Equal("keyId", exception.ParamName);
        }

        [Fact]
        public void Constructor_WhenKeyIdIsEmpty_Throws()
        {
            ArgumentException exception = Assert.Throws<ArgumentException>(
                () => new AwsKmsService(
                    _kmsClient.Object,
                    keyId: "",
                    TestCertificatePath,
                    _logger));

            Assert.Equal("keyId", exception.ParamName);
        }

        [Fact]
        public void Constructor_WhenCertificatePathIsNull_Throws()
        {
            ArgumentException exception = Assert.Throws<ArgumentNullException>(
                () => new AwsKmsService(
                    _kmsClient.Object,
                    TestKeyId,
                    certificatePath: null!,
                    _logger));

            Assert.Equal("certificatePath", exception.ParamName);
        }

        [Fact]
        public void Constructor_WhenCertificatePathIsEmpty_Throws()
        {
            ArgumentException exception = Assert.Throws<ArgumentException>(
                () => new AwsKmsService(
                    _kmsClient.Object,
                    TestKeyId,
                    certificatePath: "",
                    _logger));

            Assert.Equal("certificatePath", exception.ParamName);
        }

        [Fact]
        public void Constructor_WhenLoggerIsNull_Throws()
        {
            ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
                () => new AwsKmsService(
                    _kmsClient.Object,
                    TestKeyId,
                    TestCertificatePath,
                    logger: null!));

            Assert.Equal("logger", exception.ParamName);
        }

        [Fact]
        public async Task GetCertificateAsync_WhenCertificateFileNotFound_Throws()
        {
            using AwsKmsService service = new(
                _kmsClient.Object,
                TestKeyId,
                "/nonexistent/path/certificate.pem",
                _logger);

            await Assert.ThrowsAsync<FileNotFoundException>(
                () => service.GetCertificateAsync(CancellationToken.None));
        }

        [Fact]
        public void Dispose_DisposesKmsClient()
        {
            AwsKmsService service = new(
                _kmsClient.Object,
                TestKeyId,
                TestCertificatePath,
                _logger);

            service.Dispose();

            _kmsClient.Verify(x => x.Dispose(), Times.Once());
        }
    }
}

