using Xunit;
using UID2.Client.Utils;
using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace UID2.Client.Test
{
    public class KeyParserTests
    {
        [Fact]
        public void ParseKeyList()
        {
            var s =
                @"{""body"": [
                    {
                        ""id"": 3,
                        ""site_id"": 13,
                        ""created"": 1609459200,
                        ""activates"": 1609459210,
                        ""expires"": 1893456000,
                        ""secret"": ""o8HsvkwJ5Ulnrd0uui3GpukpwDapj+JLqb7qfN/GJKo=""
                    },
                    {
                        ""id"": 2,
                        ""site_id"": 14,
                        ""created"": 1609458200,
                        ""activates"": 1609459220,
                        ""expires"": 1893457000,
                        ""secret"": ""DD67xF8OFmbJ1/lMPQ6fGRDbJOT4kXErrYWcKdFfCUE=""
                    }
                ]}";

            var keyContainer = KeyParser.Parse(s);

            Key key;

            Assert.True(keyContainer.TryGetKey(3, out key));
            Assert.Equal(13, key.SiteId);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1609459200), key.Created);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1609459210), key.Activates);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1893456000), key.Expires);
            Assert.Equal("o8HsvkwJ5Ulnrd0uui3GpukpwDapj+JLqb7qfN/GJKo=", Convert.ToBase64String(key.Secret));

            Assert.True(keyContainer.TryGetKey(2, out key));
            Assert.Equal(14, key.SiteId);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1609458200), key.Created);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1609459220), key.Activates);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1893457000), key.Expires);
            Assert.Equal("DD67xF8OFmbJ1/lMPQ6fGRDbJOT4kXErrYWcKdFfCUE=", Convert.ToBase64String(key.Secret));
        }

        [Fact]
        public void ParseKeyListSharingEndpoint()
        {
            var s =
                @"{""body"": {
                   ""caller_site_id"": 11,
                    ""master_keyset_id"": 1,
                    ""default_keyset_id"": 99999,
                    ""token_expiry_seconds"": 1728000,
                    ""keys"": [
                    {
                        ""id"": 3,
                        ""keyset_id"": 99999,
                        ""created"": 1609459200,
                        ""activates"": 1609459210,
                        ""expires"": 1893456000,
                        ""secret"": ""o8HsvkwJ5Ulnrd0uui3GpukpwDapj+JLqb7qfN/GJKo=""
                    },
                    {
                        ""id"": 2,
                        ""keyset_id"": 1,
                        ""created"": 1609458200,
                        ""activates"": 1609459220,
                        ""expires"": 1893457000,
                        ""secret"": ""DD67xF8OFmbJ1/lMPQ6fGRDbJOT4kXErrYWcKdFfCUE=""
                    }],
                },
            ""status"": ""success""}";

            var keyContainer = KeyParser.Parse(s);

            Key key;

            Assert.Equal(11, keyContainer.CallerSiteId);
            Assert.True(keyContainer.TryGetMasterKey(DateTime.UtcNow, out var masterKey));
            Assert.Equal(2, masterKey.Id);
            Assert.True(keyContainer.TryGetDefaultKey(DateTime.UtcNow, out var defaultKey));
            Assert.Equal(3, defaultKey.Id);
            Assert.Equal(1728000, keyContainer.TokenExpirySeconds);

            Assert.True(keyContainer.TryGetKey(3, out key));
            Assert.Equal(99999, key.KeysetId);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1609459200), key.Created);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1609459210), key.Activates);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1893456000), key.Expires);
            Assert.Equal("o8HsvkwJ5Ulnrd0uui3GpukpwDapj+JLqb7qfN/GJKo=", Convert.ToBase64String(key.Secret));

            Assert.True(keyContainer.TryGetKey(2, out key));
            Assert.Equal(1, key.KeysetId);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1609458200), key.Created);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1609459220), key.Activates);
            Assert.Equal(DateTimeUtils.FromEpochSeconds(1893457000), key.Expires);
            Assert.Equal("DD67xF8OFmbJ1/lMPQ6fGRDbJOT4kXErrYWcKdFfCUE=", Convert.ToBase64String(key.Secret));
        }


        [Fact]
        public void ParseErrorKeyList()
        {
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(@"{""status"": ""error""}"));
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(@"{""body"": ""error""}"));
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(@"{""body"": [1, 2, 3]}"));
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(@"{""body"": [{}]}"));
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(@"{""body"": [{""id"": ""test""}]}"));
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(@"{""body"": [{""id"": 5}]}"));
        }

        [Fact]
        public void ParseMissingSiteData()
        {
            var json = /*lang=json,strict*/ @"{
                ""body"": {
                    ""keys"": [
                        {
                            ""id"": 3,
                            ""keyset_id"": 99999,
                            ""created"": 1609459200,
                            ""activates"": 1609459210,
                            ""expires"": 1893456000,
                            ""secret"": ""o8HsvkwJ5Ulnrd0uui3GpukpwDapj+JLqb7qfN/GJKo=""
                        }
                    ]
                }
            }";

            var keyContainer = KeyParser.Parse(json);

            var isDomainNameForSite = keyContainer.IsDomainNameAllowedForSite(1, "example.com");

            Assert.False(isDomainNameForSite);

            Assert.True(keyContainer.TryGetKey(3, out var key));
        }

        [Fact]
        public void ParseEmptySiteData()
        {
            var json = /*lang=json,strict*/ @"{
                ""body"": {
                    ""keys"": [
                        {
                            ""id"": 3,
                            ""keyset_id"": 99999,
                            ""created"": 1609459200,
                            ""activates"": 1609459210,
                            ""expires"": 1893456000,
                            ""secret"": ""o8HsvkwJ5Ulnrd0uui3GpukpwDapj+JLqb7qfN/GJKo=""
                        }
                    ],
                    ""site_data"": []
                }
            }";

            var keyContainer = KeyParser.Parse(json);

            var isDomainNameForSite = keyContainer.IsDomainNameAllowedForSite(1, "example.com");
            Assert.False(isDomainNameForSite);
            Assert.False(keyContainer.IsDomainNameAllowedForSite(1, null));

            Assert.True(keyContainer.TryGetKey(3, out var key));
        }

        [Fact]
        public void ParseSiteDataSharingEndpoint()
        {
            var s = @"{
                ""body"": {
                    ""keys"": [
                        {
                            ""id"": 3,
                            ""keyset_id"": 99999,
                            ""created"": 1609459200,
                            ""activates"": 1609459210,
                            ""expires"": 1893456000,
                            ""secret"": ""o8HsvkwJ5Ulnrd0uui3GpukpwDapj+JLqb7qfN/GJKo=""
                        }
                    ],
                    ""site_data"": [
                        {
                            ""id"": 9,
                            ""domain_names"": [""example.com""]
                        },
                        {
                            ""id"": 100,
                            ""domain_names"": [""example.org"", ""example.net""]
                        }
                    ],
                },
            }";

            var keyContainer = KeyParser.Parse(s);

            Assert.True(keyContainer.IsDomainNameAllowedForSite(9, "example.com"));
            Assert.False(keyContainer.IsDomainNameAllowedForSite(9, "example.org"));
            Assert.False(keyContainer.IsDomainNameAllowedForSite(9, "example.net"));

            Assert.False(keyContainer.IsDomainNameAllowedForSite(100, "example.com"));
            Assert.True(keyContainer.IsDomainNameAllowedForSite(100, "example.org"));
            Assert.True(keyContainer.IsDomainNameAllowedForSite(100, "example.net"));
            Assert.False(keyContainer.IsDomainNameAllowedForSite(100, null));

            Assert.True(keyContainer.TryGetKey(3, out var key));
        }

        [Fact]
        public void ParseErrorSiteData()
        {
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(/*lang=json,strict*/ @"{""body"":{""site_data"": 123}}"));
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(/*lang=json,strict*/ @"{""body"":{""site_data"": {}}}"));
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(/*lang=json,strict*/ @"{""body"":{""site_data"": [{}]}}"));
            Assert.ThrowsAny<Exception>(() => KeyParser.Parse(/*lang=json,strict*/ @"{""body"":{""site_data"": [{}]}}"));
        }
    }
}