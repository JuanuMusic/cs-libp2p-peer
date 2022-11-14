using System;
namespace LibP2P.Peer
{
	public record PeerIdInit
	{
		public KeyType Type;
		public Multiformats.Hashes.Digest Multihash;
	}
}

