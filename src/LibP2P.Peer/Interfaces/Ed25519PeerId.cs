using System;
using Multiformats.CID;
using Multiformats.Hashes;

namespace LibP2P.Peer.Interfaces
{
	public class Ed25519PeerId : BasePeerId
	{
		public Ed25519PeerId(Digest multihash, byte[]? privateKey = null)
		{
            this.Multihash = multihash;
            this.PublicKey = multihash.Bytes;
            this.PrivateKey = privateKey;
		}

        public override PeerIdType Type => PeerIdType.Ed25519;

        public override Digest Multihash { get; set; }

        public override byte[] PublicKey { get; set; }

        public override byte[] ToBytes()
        {
            throw new NotImplementedException();
        }
    }
}

