using System;
using System.Collections.Generic;

namespace UID2.Client.Utils
{
    internal static class ListUtils
    {
        // Returns index of the first element for which comp(value, listItem) returns false
        // If no such element is found, returns list.size()
        // Modelled after C++ std::upper_bound()
        public static int UpperBound<T1, T2>(List<T1> list, T2 value, Func<T2, T1, bool> comp)
        {
            int it;
            int first = 0;
            int count = list.Count;
            int step;
            while (count > 0)
            {
                step = count / 2;
                it = first + step;
                if (!comp.Invoke(value, list[it]))
                {
                    first = ++it;
                    count -= step + 1;
                }
                else
                {
                    count = step;
                }
            }
            return first;
        }
    }
}
