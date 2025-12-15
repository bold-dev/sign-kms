// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using System.CommandLine;
using System.CommandLine.Parsing;
using Amazon;
using Amazon.KeyManagementService;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sign.Core;
using Sign.SignatureProviders.AwsKms;

namespace Sign.Cli
{
    internal sealed class AwsKmsCommand : Command
    {
        internal Option<string> KeyIdOption { get; }
        internal Option<string> RegionOption { get; }
        internal Option<string> CertificatePathOption { get; }
        internal Option<string?> AccessKeyIdOption { get; }
        internal Option<string?> SecretAccessKeyOption { get; }
        internal Option<string?> SessionTokenOption { get; }
        internal Option<string?> ProfileOption { get; }

        internal Argument<List<string>?> FilesArgument { get; }

        internal AwsKmsCommand(CodeCommand codeCommand, IServiceProviderFactory serviceProviderFactory)
            : base("aws-kms", AwsKmsResources.CommandDescription)
        {
            ArgumentNullException.ThrowIfNull(codeCommand, nameof(codeCommand));
            ArgumentNullException.ThrowIfNull(serviceProviderFactory, nameof(serviceProviderFactory));

            KeyIdOption = new Option<string>("--aws-kms-key", "-akk")
            {
                Description = AwsKmsResources.KeyIdOptionDescription,
                Required = true
            };
            RegionOption = new Option<string>("--aws-kms-region", "-akr")
            {
                Description = AwsKmsResources.RegionOptionDescription,
                Required = true
            };
            CertificatePathOption = new Option<string>("--aws-kms-certificate", "-akc")
            {
                Description = AwsKmsResources.CertificatePathOptionDescription,
                Required = true,
                CustomParser = ParseCertificatePath
            };
            AccessKeyIdOption = new Option<string?>("--aws-access-key-id", "-aki")
            {
                Description = AwsKmsResources.AccessKeyIdOptionDescription
            };
            SecretAccessKeyOption = new Option<string?>("--aws-secret-access-key", "-ask")
            {
                Description = AwsKmsResources.SecretAccessKeyOptionDescription
            };
            SessionTokenOption = new Option<string?>("--aws-session-token", "-ast")
            {
                Description = AwsKmsResources.SessionTokenOptionDescription
            };
            ProfileOption = new Option<string?>("--aws-profile", "-ap")
            {
                Description = AwsKmsResources.ProfileOptionDescription
            };
            FilesArgument = new Argument<List<string>?>("file(s)")
            {
                Description = Resources.FilesArgumentDescription,
                Arity = ArgumentArity.OneOrMore
            };

            Options.Add(KeyIdOption);
            Options.Add(RegionOption);
            Options.Add(CertificatePathOption);
            Options.Add(AccessKeyIdOption);
            Options.Add(SecretAccessKeyOption);
            Options.Add(SessionTokenOption);
            Options.Add(ProfileOption);

            Arguments.Add(FilesArgument);

            SetAction((ParseResult parseResult, CancellationToken cancellationToken) =>
            {
                List<string>? filesArgument = parseResult.GetValue(FilesArgument);

                if (filesArgument is not { Count: > 0 })
                {
                    Console.Error.WriteLine(Resources.MissingFileValue);

                    return Task.FromResult(ExitCode.InvalidOptions);
                }

                // Some of the options are required and that is why we can safely use
                // the null-forgiving operator (!) to simplify the code.
                string keyId = parseResult.GetValue(KeyIdOption)!;
                string region = parseResult.GetValue(RegionOption)!;
                string certificatePath = parseResult.GetValue(CertificatePathOption)!;
                string? accessKeyId = parseResult.GetValue(AccessKeyIdOption);
                string? secretAccessKey = parseResult.GetValue(SecretAccessKeyOption);
                string? sessionToken = parseResult.GetValue(SessionTokenOption);
                string? profile = parseResult.GetValue(ProfileOption);

                // Validate the region
                RegionEndpoint? regionEndpoint = RegionEndpoint.GetBySystemName(region);
                if (regionEndpoint is null || regionEndpoint.DisplayName == "Unknown")
                {
                    Console.Error.WriteLine(AwsKmsResources.InvalidRegion);
                    return Task.FromResult(ExitCode.InvalidOptions);
                }

                // Create AWS credentials
                AWSCredentials credentials = CreateAwsCredentials(accessKeyId, secretAccessKey, sessionToken, profile);

                serviceProviderFactory.AddServices(services =>
                {
                    services.AddSingleton<IAmazonKeyManagementService>(_ =>
                    {
                        return new AmazonKeyManagementServiceClient(credentials, regionEndpoint);
                    });

                    services.AddSingleton<AwsKmsService>(serviceProvider =>
                    {
                        return new AwsKmsService(
                            serviceProvider.GetRequiredService<IAmazonKeyManagementService>(),
                            keyId,
                            certificatePath,
                            serviceProvider.GetRequiredService<ILogger<AwsKmsService>>());
                    });
                });

                AwsKmsServiceProvider awsKmsServiceProvider = new();

                return codeCommand.HandleAsync(parseResult, serviceProviderFactory, awsKmsServiceProvider, filesArgument);
            });
        }

        private static AWSCredentials CreateAwsCredentials(
            string? accessKeyId,
            string? secretAccessKey,
            string? sessionToken,
            string? profile)
        {
            // If explicit credentials are provided, use them
            if (!string.IsNullOrEmpty(accessKeyId) && !string.IsNullOrEmpty(secretAccessKey))
            {
                if (!string.IsNullOrEmpty(sessionToken))
                {
                    return new SessionAWSCredentials(accessKeyId, secretAccessKey, sessionToken);
                }

                return new BasicAWSCredentials(accessKeyId, secretAccessKey);
            }

            // If a profile is specified, use it
            if (!string.IsNullOrEmpty(profile))
            {
                CredentialProfileStoreChain chain = new();
                if (chain.TryGetAWSCredentials(profile, out AWSCredentials? profileCredentials))
                {
                    return profileCredentials;
                }

                throw new InvalidOperationException($"AWS profile '{profile}' not found.");
            }

            // Otherwise, use the default credential chain (env vars, instance profile, etc.)
            return FallbackCredentialsFactory.GetCredentials();
        }

        private static string? ParseCertificatePath(ArgumentResult result)
        {
            if (result.Tokens.Count != 1 ||
                string.IsNullOrWhiteSpace(result.Tokens[0].Value))
            {
                result.AddError(AwsKmsResources.InvalidCertificatePath);
                return null;
            }

            string path = result.Tokens[0].Value;

            // If it's a relative path, make it absolute based on current directory
            if (!Path.IsPathRooted(path))
            {
                path = Path.GetFullPath(path);
            }

            if (!File.Exists(path))
            {
                result.AddError(string.Format(AwsKmsResources.CertificateFileNotFound, path));
                return null;
            }

            return path;
        }
    }
}

