using System;
using Multiformats.CID;
using Multiformats.Hashes;

namespace LibP2P.Peer.Interfaces
{
    public class Secp256k1PeerId : BasePeerId
    {
        public Secp256k1PeerId(Digest multihash)
        {
            this.Multihash = multihash;
        }

        public override PeerIdType Type => PeerIdType.secp256k1;

        public override byte[] ToBytes()
        {
            throw new NotImplementedException();
        }
    }
}

