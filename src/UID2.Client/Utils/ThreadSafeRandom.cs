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
