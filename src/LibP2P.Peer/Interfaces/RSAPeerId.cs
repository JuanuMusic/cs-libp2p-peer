using System;
using Multiformats.CID;
using Multiformats.Hashes;

namespace LibP2P.Peer.Interfaces
{
    public class RSAPeerId : BasePeerId
    {
        public RSAPeerId(Digest multihash)
        {
            this.Multihash = multihash;
        }

        public override PeerIdType Type => PeerIdType.RSA;

        public override byte[] ToBytes()
        {
            throw new NotImplementedException();
        }
    }
}

