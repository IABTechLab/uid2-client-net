using System;

namespace UID2.Client.Utils
{
    internal static class DateTimeUtils
    {
        internal static DateTime FromEpochSeconds(long seconds)
        {
            var d = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            return d.AddSeconds(seconds);
        }

        internal static DateTime FromEpochMilliseconds(long milliseconds)
        {
            var d = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            return d.AddMilliseconds(milliseconds);
        }

        internal static long DateTimeToEpochSeconds(DateTime dateTime)
        {
            return (long)dateTime.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc)).TotalSeconds;
        }

        internal static long DateTimeToEpochMilliseconds(DateTime dateTime)
        {
            return (long)dateTime.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc)).TotalMilliseconds;
        }
    }
}
