using System;
using System.Collections.Generic;
using System.Text;

namespace UID2.Client
{
    public struct RefreshResponse
    {
        private readonly bool _success;
        private readonly string _reason;

        private RefreshResponse(bool success, string reason)
        {
            _success = success;
            _reason = reason;
        }

        public static RefreshResponse MakeSuccess()
        {
            return new RefreshResponse(true, string.Empty);
        }

        public static RefreshResponse MakeError(string reason)
        {
            return new RefreshResponse(false, reason);
        }

        public bool Success => _success;
        public string Reason => _reason;
    }
}
