using System;

namespace UID2.Client
{
    internal interface IKeyContainer
    {
        bool IsValid(DateTime now);
        bool TryGetKey(long id, out Key key);
        bool TryGetActiveSiteKey(int siteId, DateTime now, out Key key);
    }
}
