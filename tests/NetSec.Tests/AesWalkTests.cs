using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Labs;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>What the acceptance clauses leave open. They hold the FIPS 197 values, the BCL and the reference field. These hold the walk's own edges.</summary>
    public class AesWalkTests
    {
        static readonly byte[] Key = Hex.Decode("2b7e151628aed2a6abf7158809cf4f3c");
        static readonly byte[] Block = Hex.Decode("3243f6a8885a308d313198a2e0370734");

        [Fact]
        public void A_guard_that_fires_names_the_code()
        {
            NetSecException e = Assert.Throws<NetSecException>(() => AesKey.RequireSame(new byte[] { 1 }, new byte[] { 2 }));
            Assert.Equal(ErrorCodes.AesWalkDiverged, e.Error.Code);
        }

        [Fact]
        public void A_longer_buffer_walks_its_first_block_as_the_real_path_does()
        {
            byte[] longer = new byte[20];
            System.Array.Copy(Block, longer, 16);
            AesBlockWalk walk = new AesKey(Key).WalkEncrypt(longer);
            Assert.Equal(Hex.Encode(Block), Hex.Encode(walk.Input));
            Assert.Equal("3925841d02dc09fbdc118597196a0b32", Hex.Encode(walk.Output));
        }

        [Fact]
        public void Each_step_keeps_its_own_state()
        {
            AesBlockWalk walk = new AesKey(Key).WalkEncrypt(Block);
            Assert.Equal(40, walk.Steps.Length);
            string first = Hex.Encode(walk.Steps[0].State);
            walk.Steps[1].State[0] ^= 0xff;
            Assert.Equal(first, Hex.Encode(walk.Steps[0].State));
            Assert.NotEqual(first, Hex.Encode(walk.Output));
        }

        [Fact]
        public void A_caller_cannot_change_the_tables_through_a_copy()
        {
            AesKey.SubstitutionTable()[0] ^= 0xff;
            Assert.Equal(0x63, AesKey.SubstitutionTable()[0]);
        }

        [Fact]
        public void No_inverse_input_gives_no_inverse_walk()
        {
            AesBlockPair pair = AesWalks.Block(Key, Block, null);
            Assert.Null(pair.Inverse);
            Assert.Equal(128, pair.KeyBits);
            Assert.Equal(44, pair.KeyWords.Length);
        }

        [Fact]
        public void One_round_constant_has_no_doubling()
        {
            Assert.Empty(AesKey.RoundConstantSteps(1));
        }

        [Fact]
        public void A_term_of_factor_1_has_no_doubling_and_picks_its_input()
        {
            AesTerm one = AesKey.MixTerms(Hex.Decode("d4bf5d30e0b452aeb84111f11e2798e5"), false)[0].Terms[2];
            Assert.Equal(1, one.Factor);
            Assert.Empty(one.Doublings);
            Assert.Equal(new byte[] { 0x5d }, one.Picks);
            Assert.Equal(new byte[] { 0x5d }, one.Sums);
            Assert.False(one.Reduced);
        }
    }
}
