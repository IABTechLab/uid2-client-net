using System;
using System.Collections.Generic;

namespace UID2.Client
{
    internal class Site
    {
        private readonly HashSet<string> _domainNames;

        public Site(int id, IEnumerable<string> domainNames)
        {
            Id = id;
            _domainNames = new HashSet<string>(domainNames);
        }

        public int Id { get; }

        public bool AllowDomainName(string domainName) => _domainNames.Contains(domainName);
    }
}
