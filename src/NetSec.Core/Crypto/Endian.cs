namespace NetSec.Crypto
{
    /// <summary>Reads and writes words in a byte array. SHA-1 and SHA-2 are big-endian. MD5 is little-endian.</summary>
    static class Endian
    {
        public static uint LoadBe32(byte[] b, int off)
        {
            return ((uint)b[off] << 24) | ((uint)b[off + 1] << 16) | ((uint)b[off + 2] << 8) | b[off + 3];
        }

        public static uint LoadLe32(byte[] b, int off)
        {
            return b[off] | ((uint)b[off + 1] << 8) | ((uint)b[off + 2] << 16) | ((uint)b[off + 3] << 24);
        }

        public static ulong LoadBe64(byte[] b, int off)
        {
            return ((ulong)LoadBe32(b, off) << 32) | LoadBe32(b, off + 4);
        }

        public static void StoreBe32(uint v, byte[] b, int off)
        {
            b[off] = (byte)(v >> 24); b[off + 1] = (byte)(v >> 16); b[off + 2] = (byte)(v >> 8); b[off + 3] = (byte)v;
        }

        public static void StoreLe32(uint v, byte[] b, int off)
        {
            b[off] = (byte)v; b[off + 1] = (byte)(v >> 8); b[off + 2] = (byte)(v >> 16); b[off + 3] = (byte)(v >> 24);
        }

        public static void StoreBe64(ulong v, byte[] b, int off)
        {
            StoreBe32((uint)(v >> 32), b, off);
            StoreBe32((uint)v, b, off + 4);
        }

        public static void StoreLe64(ulong v, byte[] b, int off)
        {
            StoreLe32((uint)v, b, off);
            StoreLe32((uint)(v >> 32), b, off + 4);
        }
    }
}
