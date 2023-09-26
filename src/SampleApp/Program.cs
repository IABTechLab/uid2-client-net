using System;
using System.Threading;
using UID2.Client;

namespace app
{
    class Program
    {
        static string _baseUrl;
        static string _authKey;
        static string _secretKey;
        static string _advertisingToken;
        static string _domain;

        static void StartExample(string name)
        {
            Console.WriteLine();
            Console.WriteLine("EXAMPLE: " + name);
            Console.WriteLine();
            Console.Out.Flush();
        }

        static void ExampleBasicRefresh()
        {
            StartExample("Basic keys refresh and decrypt token");

            var client = UID2ClientFactory.Create(_baseUrl, _authKey, _secretKey);
            var refreshResult = client.Refresh();
            if (!refreshResult.Success)
            {
                Console.WriteLine($"Failed to refresh keys: {refreshResult.Reason}");
                return;
            }

            var result = client.Decrypt(_advertisingToken, _domain);
            Console.WriteLine($"DecryptedSuccess={result.Success} Status={result.Status}");
            Console.WriteLine($"UID={result.Uid}");
            Console.WriteLine($"EstablishedAt={result.Established}");
            Console.WriteLine($"SiteId={result.SiteId}");
            Console.WriteLine($"IsClientSideGenerated={result.IsClientSideGenerated}");
        }

        static void ExampleAutoRefresh()
        {
            StartExample("Automatic background keys refresh");

            var client = UID2ClientFactory.Create(_baseUrl, _authKey, _secretKey);

            var refreshThread = new Thread(() =>
            {
                for (int i = 0; i < 8; ++i)
                {
                    Thread.Sleep(TimeSpan.FromSeconds(3));
                    var refreshResult = client.Refresh();
                    Console.WriteLine($"Refresh keys, success={refreshResult.Success}");
                    Console.Out.Flush();
                }
            });
            refreshThread.Start();

            for (int i = 0; i < 5; ++i)
            {
                var result = client.Decrypt(_advertisingToken, _domain);
                Console.WriteLine($"DecryptSuccess={result.Success} Status={result.Status} UID={result.Uid}");
                Console.Out.Flush();
                Thread.Sleep(TimeSpan.FromSeconds(5));
            }

            refreshThread.Join();
        }

        static void ExampleSharing()
        { 
            StartExample("Encrypt and Decrypt UIDs for Sharing");

            var client = UID2ClientFactory.Create(_baseUrl, _authKey, _secretKey);
            var refreshResult = client.Refresh();
            if (!refreshResult.Success)
            {
                Console.WriteLine($"Failed to refresh keys: {refreshResult.Reason}");
                return;
            }

            var rawUid = "P2xdbu2ldlpXV1z6n3bET7T1g0xfqmldZPDdPTvydRQ=";
            var encrypted = client.Encrypt(rawUid);

            if (!encrypted.Success)
            {
                Console.WriteLine($"Failed to encrypt data: {encrypted.Status}");
                return;
            }

            var decrypted = client.Decrypt(encrypted.EncryptedData);
            if (!decrypted.Success)
            {
                Console.WriteLine($"Failed to decrypt data: {decrypted.Status}");
                return;
            }

            Console.WriteLine($"Original data: {rawUid}");
            Console.WriteLine($"Encrypted    : {encrypted.EncryptedData}");
            Console.WriteLine($"Decrypted    : {decrypted.Uid}");
            Console.WriteLine($"Encrypted at : {decrypted.Established}");
        }

        static int Main(string[] args)
        {
            if (args.Length < 4)
            {
                Console.Error.WriteLine("Usage: test-client <base-url> <auth-key> <secret-key> <ad-token> [<domain-name>]");
                return 1;
            }

            _baseUrl = args[0];
            _authKey = args[1];
            _secretKey = args[2];
            _advertisingToken = args[3];
            if (args.Length >= 5)
            {
                _domain = args[4];
            }

            ExampleBasicRefresh();
            ExampleAutoRefresh();
            ExampleSharing();

            return 0;

        }
    }
}
