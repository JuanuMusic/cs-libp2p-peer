using System;
using System.Linq;
using System.Security.Cryptography;
using Multiformats.CID;
using Multiformats.Hashes;
using Newtonsoft.Json;

namespace LibP2P.Peer.Interfaces
{
    public record PeerIdRecord
    {
        public byte[] Hash;
        public int? Type;
        public byte[] PrivateKey;
        public byte[] PublicKey;
    }
	public abstract class BasePeerId
	{
        // these values are from https://github.com/multiformats/multicodec/blob/master/table.csv
        public const int LIBP2P_KEY_CODE = 0x72;

        public virtual PeerIdType Type { get; set; }
        public virtual Digest? Multihash { get; set; }
        public virtual byte[]? PrivateKey { get; set; }
        public virtual byte[]? PublicKey { get; set; }

        // return self-describing String representation
        // in default format from RFC 0001: https://github.com/libp2p/specs/pull/209
        public virtual CID ToCID()
            => CID.CreateV1(LIBP2P_KEY_CODE, this.Multihash);

        public abstract byte[] ToBytes();

        public override string ToString()
        {
            if (Multihash == null) return String.Empty;
            return Multiformats.Base.Multibase.EncodeRaw(Multiformats.Base.MultibaseEncoding.Base58Btc, this.Multihash.Bytes);
        }

        public override bool Equals(object obj)
        {
            if (obj.GetType() == typeof(byte[]))
                return this.Multihash.Bytes.SequenceEqual((byte[])obj);
            else if (obj.GetType() == typeof(string))
                return PeerId.FromString((string)obj).Equals(this);
            else if (typeof(BasePeerId).IsAssignableFrom(obj.GetType()))
                return this.Multihash.Bytes.SequenceEqual(((BasePeerId)obj).Multihash.Bytes);
            return false;
        }
        private PeerIdRecord ToRecord()
            => new PeerIdRecord {
                Hash = this.Multihash.Bytes,
                PrivateKey = this.PrivateKey,
                PublicKey = this.PublicKey,
                Type = (int)this.Type };

        public string ToJSON()
            => JsonConvert.SerializeObject(this.ToRecord());
    }
}

