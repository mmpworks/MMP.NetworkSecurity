namespace NetSec.Crypto
{
    public interface IRandomSource
    {
        void Fill(byte[] b, int off, int n);
    }
}
