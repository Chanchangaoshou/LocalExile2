using GameServer.Core.Protocol.Instance;

namespace GameServer.Core.Tests;

public class AreaInstanceStatsTests
{
    [Fact]
    public void Empty_league_stats_encode_like_no_stats()
    {
        byte[] ordinary = new AreaInstance(1, 0x235c, 1, 0).Encode();
        Assert.Equal(ordinary, new AreaInstance(1, 0x235c, 1, 0, LeagueStats: new Dictionary<uint, int>()).Encode());
    }

    [Fact]
    public void League_stats_are_not_encoded_until_the_0_5_5_pair_list_format_is_reversed()
    {
        // The 0.5.5 client reads the pair lists as objects (+0x130/+0x150/+0x170 of the 0x1e area
        // class, read 0x14211d340), not as the older client's compact pairs: refuse loudly instead
        // of emitting a guessed format.
        Assert.Throws<NotSupportedException>(() => new AreaInstance(1, 0x235c, 1, 0, LeagueStats: new Dictionary<uint, int>
        {
            [21146] = 1 // league_enable_alt_ascendancies in the verified target client's Stats.dat
        }).Encode());
    }
}
