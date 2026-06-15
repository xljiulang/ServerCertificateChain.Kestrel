using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace ServerCertificateChain.Kestrel
{
    sealed class ConcurrentCache<TKey, TValue> where TKey : notnull
    {
        private readonly ConcurrentDictionary<TKey, Lazy<TValue>> _cache;

        public ConcurrentCache()
        {
            this._cache = [];
        }

        public ConcurrentCache(IEqualityComparer<TKey> comparer)
        {
            this._cache = new ConcurrentDictionary<TKey, Lazy<TValue>>(comparer);
        }

        public TValue GetOrAdd(TKey key, Func<TKey, TValue> valueFactory)
        {
            return this._cache.GetOrAdd(key, k => new Lazy<TValue>(() => valueFactory.Invoke(k), isThreadSafe: true)).Value;
        }

        public void Clear()
        {
            this._cache.Clear();
        }
    }
}