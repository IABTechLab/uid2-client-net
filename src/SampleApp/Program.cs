// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

using System;
using System.Text;
using System.Threading;
using UID2.Client;

namespace app
{
    class Program
    {
        static string _baseUrl;
        static string _authKey;
        static string _advertisingToken;

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

            var client = UID2ClientFactory.Create(_baseUrl, _authKey);
            var refreshResult = client.Refresh();
            if (!refreshResult.Success)
            {
                Console.WriteLine($"Failed to refresh keys: {refreshResult.Reason}");
                return;
            }

            var result = client.Decrypt(_advertisingToken, DateTime.UtcNow);
            Console.WriteLine($"DecryptedSuccess={result.Success} Status={result.Status}");
            Console.WriteLine($"UID={result.Uid}");
            Console.WriteLine($"EstablishedAt={result.Established}");
        }

        static void ExampleAutoRefresh()
        {
            StartExample("Automatic background keys refresh");

            var client = UID2ClientFactory.Create(_baseUrl, _authKey);

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
                var result = client.Decrypt(_advertisingToken, DateTime.UtcNow);
                Console.WriteLine($"DecryptSuccess={result.Success} Status={result.Status} UID={result.Uid}");
                Console.Out.Flush();
                Thread.Sleep(TimeSpan.FromSeconds(5));
            }

            refreshThread.Join();
        }

        static void ExampleEncryptDecryptData()
        {
            StartExample("Encrypt and Decrypt Data");

            var client = UID2ClientFactory.Create(_baseUrl, _authKey);
            var refreshResult = client.Refresh();
            if (!refreshResult.Success)
            {
                Console.WriteLine($"Failed to refresh keys: {refreshResult.Reason}");
                return;
            }

            var data = "Hello World!";
            var encrypted = client.EncryptData(EncryptionDataRequest.ForData(Encoding.UTF8.GetBytes(data)).WithAdvertisingToken(_advertisingToken));
            if (!encrypted.Success)
            {
                Console.WriteLine($"Failed to encrypt data: {encrypted.Status}");
                return;
            }

            var decrypted = client.DecryptData(encrypted.EncryptedData);
            if (!decrypted.Success)
            {
                Console.WriteLine($"Failed to decrypt data: {decrypted.Status}");
                return;
            }

            Console.WriteLine($"Original data: {data}");
            Console.WriteLine($"Encrypted    : {encrypted.EncryptedData}");
            Console.WriteLine($"Decrypted    : {Encoding.UTF8.GetString(decrypted.DecryptedData)}");
            Console.WriteLine($"Encrypted at : {decrypted.EncryptedAt}");
        }

        static int Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.Error.WriteLine("Usage: test-client <base-url> <auth-key> <ad-token>");
                return 1;
            }

            _baseUrl = args[0];
            _authKey = args[1];
            _advertisingToken = args[2];

            ExampleBasicRefresh();
            ExampleAutoRefresh();
            ExampleEncryptDecryptData();

            return 0;

        }
    }
}
