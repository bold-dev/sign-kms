// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Amazon.KeyManagementService;
using Microsoft.Extensions.Logging;
using Sign.Core;

namespace Sign.SignatureProviders.AwsKms
{
    internal sealed class AwsKmsService : ISignatureAlgorithmProvider, ICertificateProvider, IDisposable
    {
        private readonly IAmazonKeyManagementService _kmsClient;
        private readonly string _keyId;
        private readonly string _certificatePath;
        private readonly ILogger<AwsKmsService> _logger;
        private readonly SemaphoreSlim _mutex = new(1);
        private X509Certificate2? _certificate;

        internal AwsKmsService(
            IAmazonKeyManagementService kmsClient,
            string keyId,
            string certificatePath,
            ILogger<AwsKmsService> logger)
        {
            ArgumentNullException.ThrowIfNull(kmsClient, nameof(kmsClient));
            ArgumentException.ThrowIfNullOrEmpty(keyId, nameof(keyId));
            ArgumentException.ThrowIfNullOrEmpty(certificatePath, nameof(certificatePath));
            ArgumentNullException.ThrowIfNull(logger, nameof(logger));

            _kmsClient = kmsClient;
            _keyId = keyId;
            _certificatePath = certificatePath;
            _logger = logger;
        }

        public void Dispose()
        {
            _mutex.Dispose();
            _certificate?.Dispose();
            _kmsClient.Dispose();
            GC.SuppressFinalize(this);
        }

        public Task<X509Certificate2> GetCertificateAsync(CancellationToken cancellationToken)
        {
            if (_certificate is not null)
            {
                return Task.FromResult(new X509Certificate2(_certificate)); // clone it as it's disposable
            }

            return GetCertificateInternalAsync(cancellationToken);
        }

        private async Task<X509Certificate2> GetCertificateInternalAsync(CancellationToken cancellationToken)
        {
            await _mutex.WaitAsync(cancellationToken);

            try
            {
                if (_certificate is null)
                {
                    Stopwatch stopwatch = Stopwatch.StartNew();

                    _logger.LogTrace(Resources.LoadingCertificate);

                    if (!File.Exists(_certificatePath))
                    {
                        throw new FileNotFoundException(
                            string.Format(Resources.CertificateFileNotFound, _certificatePath),
                            _certificatePath);
                    }

                    _certificate = new X509Certificate2(_certificatePath);

                    _logger.LogTrace(Resources.LoadedCertificate, stopwatch.Elapsed.TotalMilliseconds);

                    _logger.LogTrace($"{Resources.CertificateDetails}{Environment.NewLine}{_certificate.ToString(verbose: true)}");
                }
            }
            finally
            {
                _mutex.Release();
            }

            return new X509Certificate2(_certificate); // clone it as it's disposable
        }

        public async Task<RSA> GetRsaAsync(CancellationToken cancellationToken)
        {
            using X509Certificate2 certificate = await GetCertificateAsync(cancellationToken);

            RSA? rsaPublicKey = certificate.GetRSAPublicKey();
            if (rsaPublicKey is null)
            {
                throw new InvalidOperationException(Resources.CertificateDoesNotContainRsaPublicKey);
            }

            return new RSAAwsKms(_kmsClient, _keyId, rsaPublicKey);
        }
    }
}

