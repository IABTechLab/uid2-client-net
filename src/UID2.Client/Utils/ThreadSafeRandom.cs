using System;

namespace UID2.Client.Utils
{
    /// <summary>
    /// Allow for requesting random numbers in a thread-safe way.
    /// 
    /// This class is loosly based off of the "RandomGen2" example found at:
    ///     http://blogs.msdn.com/b/pfxteam/archive/2009/02/19/9434171.aspx
    /// 
    /// Example usage:
    ///     var randInt = ThreadSafeRandom.PerThread.Next();
    /// 
    /// </summary>
    internal static class ThreadSafeRandom
    {
        // Used to generate seeds for each thread-local random instance.
        // Not using RandomTTD here to ensure that we still generate with random seeds while testing.
        private static readonly Random GlobalSeeder = new Random();

        // Use a distinct random object per thread, to avoid use of global locks.
        [ThreadStatic]
        private static Random PerThreadInstance;

        /// <summary>
        /// Property used to get the thread safe random instance.
        /// </summary>
        public static Random PerThread
        {
            get
            {
                if (ThreadSafeRandom.PerThreadInstance == null)
                {
                    int seed;
                    lock (ThreadSafeRandom.GlobalSeeder)
                    {
                        seed = ThreadSafeRandom.GlobalSeeder.Next();
                    }

                    ThreadSafeRandom.PerThreadInstance = new Random(seed);
                }

                return ThreadSafeRandom.PerThreadInstance;
            }
        }
    }
}
