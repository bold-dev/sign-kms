// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using Amazon.KeyManagementService;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using Sign.TestInfrastructure;

namespace Sign.SignatureProviders.AwsKms.Test
{
    public class AwsKmsServiceProviderTests
    {
        private readonly AwsKmsServiceProvider _provider = new();
        private readonly IServiceProvider serviceProvider;

        public AwsKmsServiceProviderTests()
        {
            ServiceCollection services = new();
            services.AddSingleton<ILogger<AwsKmsService>>(new TestLogger<AwsKmsService>());
            services.AddSingleton<AwsKmsService>(sp =>
            {
                return new AwsKmsService(
                    Mock.Of<IAmazonKeyManagementService>(),
                    "test-key-id",
                    "/path/to/certificate.pem",
                    sp.GetRequiredService<ILogger<AwsKmsService>>());
            });
            serviceProvider = services.BuildServiceProvider();
        }

        [Fact]
        public void GetSignatureAlgorithmProvider_WhenServiceProviderIsNull_Throws()
        {
            ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
                () => _provider.GetSignatureAlgorithmProvider(serviceProvider: null!));

            Assert.Equal("serviceProvider", exception.ParamName);
        }

        [Fact]
        public void GetSignatureAlgorithmProvider_WhenServiceProviderIsValid_ReturnsSameInstance()
        {
            AwsKmsServiceProvider provider = new();

            Assert.IsType<AwsKmsService>(_provider.GetSignatureAlgorithmProvider(serviceProvider));
        }

        [Fact]
        public void GetCertificateProvider_WhenServiceProviderIsNull_Throws()
        {
            ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
                () => _provider.GetCertificateProvider(serviceProvider: null!));

            Assert.Equal("serviceProvider", exception.ParamName);
        }

        [Fact]
        public void GetCertificateProvider_WhenServiceProviderIsValid_ReturnsSameInstance()
        {
            Assert.IsType<AwsKmsService>(_provider.GetCertificateProvider(serviceProvider));
        }
    }
}

