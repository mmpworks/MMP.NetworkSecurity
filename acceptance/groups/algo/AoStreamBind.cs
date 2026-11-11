using System;
using System.Reflection;

namespace Acceptance
{
    /// <summary>One state object (CbcChain or CtrCounter), with its Init and Clear and the Modes overload that takes it, closed over the key.</summary>
    public sealed class AoStreamSeam
    {
        public Action<byte[], int> Init;
        public Action Clear;
        public Action<byte[], int, int, byte[], int> Call;
    }

    /// <summary>
    /// Binds a streamed form of PRD 7.3 item 15 by its shape: a static void overload method(key, state, byte[], int, int, byte[], int) on
    /// the modes type, and a public sealed state class with a public constructor (), void Init(byte[], int) and void Clear(). It names no
    /// product type, so the selftest runs the same code on stand-in types before the product has the forms.
    /// </summary>
    public static class AoStreamBind
    {
        static readonly Type B = typeof(byte[]), I = typeof(int);

        static NotRunException NotConfirmed(string what) { return new NotRunException("SIGNATURE_NOT_CONFIRMED", what + " (PRD 7.3 item 15)"); }

        /// <summary>The overload, or null when the state type or the overload does not exist. Another shape is SIGNATURE_NOT_CONFIRMED.</summary>
        static MethodInfo Overload(Type modes, Type keyType, Type state, string method)
        {
            if (state == null) return null;
            MethodInfo m = modes.GetMethod(method, new[] { keyType, state, B, I, I, B, I });
            if (m == null) return null;
            if (!m.IsStatic || m.ReturnType != typeof(void)) throw NotConfirmed(modes.Name + "." + method + " with a " + state.Name + " is not a static void method");
            if (!state.IsClass || !state.IsPublic || !state.IsSealed || state.IsAbstract) throw NotConfirmed(state.Name + " is not a public sealed class");
            return m;
        }

        /// <summary>One new state object and the overload, closed over the key. Null when the state type or the overload does not exist.</summary>
        public static AoStreamSeam TryBind(Type modes, object key, Type state, string method)
        {
            MethodInfo m = Overload(modes, key.GetType(), state, method);
            if (m == null) return null;
            ConstructorInfo ctor = state.GetConstructor(Type.EmptyTypes);
            MethodInfo init = state.GetMethod("Init", new[] { B, I }), clear = state.GetMethod("Clear", Type.EmptyTypes);
            if (ctor == null || init == null || clear == null || init.IsStatic || clear.IsStatic || init.ReturnType != typeof(void) || clear.ReturnType != typeof(void))
                throw NotConfirmed(state.Name + " lacks a public constructor (), void Init(byte[], int) or void Clear()");
            object s = ctor.Invoke(null);
            AoStreamSeam seam = new AoStreamSeam();
            seam.Init = (Action<byte[], int>)Delegate.CreateDelegate(typeof(Action<byte[], int>), s, init);
            seam.Clear = (Action)Delegate.CreateDelegate(typeof(Action), s, clear);
            seam.Call = Close(m, key, s, state);
            return seam;
        }

        /// <summary>The overload, closed over the key and a null state object. Null when the state type or the overload does not exist.</summary>
        public static Action<byte[], int, int, byte[], int> TryBindNullState(Type modes, object key, Type state, string method)
        {
            MethodInfo m = Overload(modes, key.GetType(), state, method);
            return m == null ? null : Close(m, key, null, state);
        }

        static Action<byte[], int, int, byte[], int> Close(MethodInfo m, object key, object s, Type state)
        {
            MethodInfo close = typeof(AoStreamBind).GetMethod("CloseStream", BindingFlags.NonPublic | BindingFlags.Static);
            return (Action<byte[], int, int, byte[], int>)close.MakeGenericMethod(key.GetType(), state).Invoke(null, new object[] { m, key, s });
        }

        /// <summary>A typed open delegate on the overload, wrapped so that a call allocates nothing (a reflection call allocates its argument array).</summary>
        static Action<byte[], int, int, byte[], int> CloseStream<TKey, TState>(MethodInfo m, TKey k, TState state)
        {
            Action<TKey, TState, byte[], int, int, byte[], int> d =
                (Action<TKey, TState, byte[], int, int, byte[], int>)Delegate.CreateDelegate(typeof(Action<TKey, TState, byte[], int, int, byte[], int>), m);
            return delegate (byte[] i, int io, int n, byte[] o, int oo) { d(k, state, i, io, n, o, oo); };
        }
    }
}
