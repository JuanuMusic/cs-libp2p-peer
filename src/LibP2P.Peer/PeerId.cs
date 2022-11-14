using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using LibP2P.Peer.Interfaces;
using Multiformats.Base;
using Multiformats.CID;
using Multiformats.Hashes;

namespace LibP2P.Peer
{
    public abstract class PeerId : BasePeerId
    {

        const int MARSHALLED_ED225519_PUBLIC_KEY_LENGTH = 36;
        const int MARSHALLED_SECP256K1_PUBLIC_KEY_LENGTH = 37;

        public int CompareTo(PeerId other) => string.Compare(ToString(MultibaseEncoding.Base16Upper), other.ToString(MultibaseEncoding.Base16Upper), StringComparison.Ordinal);

        private readonly byte[] _value;

        //    public PeerId(byte[] bytes)
        //    {
        //        _value = bytes;
        //    }

        //    public PeerId(string s)
        //        : this(Encoding.UTF8.GetBytes(s))
        //    {
        //    }

        //    public PeerId(Multihash mh)
        //        : this((byte[])mh)
        //    {
        //    }

        //    public PeerId(PublicKey pk)
        //        : this(Multihash.Sum<SHA2_256>(pk.Bytes))
        //    {
        //    }

        //    public PeerId(PrivateKey sk)
        //        : this(sk.GetPublic())
        //    {
        //    }

        //    public int CompareTo(PeerId other) => string.Compare(ToString(MultibaseEncoding.Base16Upper), other.ToString(MultibaseEncoding.Base16Upper), StringComparison.Ordinal);

        //    public bool Equals(PeerId other) => _value.SequenceEqual(other?._value ?? Array.Empty<byte>());

        public bool Equals(PeerId obj)
        {
            var other = (PeerId)obj;
            return other != null && Equals(other);
        }

        //    public override int GetHashCode() => _value.GetHashCode();

        //public override string ToString()
        //{
        //    var id = ToString(MultibaseEncoding.Base58Btc);
        //    //if (id.StartsWith("Qm"))
        //    //    id = id.Substring(2);

        //    var max = Math.Max(6, id.Length);
        //    return id.Substring(0, max);
        //}

        public string ToString(MultibaseEncoding encoding) => Multibase.EncodeRaw(encoding, _value);


        //    public bool MatchesPrivateKey(PrivateKey sk) => MatchesPublicKey(sk.GetPublic());
        //    public bool MatchesPublicKey(PublicKey pk) => new PeerId(pk).Equals(this);

        //    public static PeerId Decode(string s)
        //    {
        //        Multihash mh;
        //        return Multihash.TryParse(s, out mh) ? new PeerId(mh) : new PeerId(Multibase.DecodeRaw(MultibaseEncoding.Base16Upper, s.ToUpper()));
        //    }

        //    public static implicit operator PeerId(string value) => new PeerId(value);
        //    public static implicit operator string(PeerId id) => Encoding.UTF8.GetString(id._value);
        //    public static implicit operator PeerId(byte[] bytes) => new PeerId(bytes);
        //    public static implicit operator byte[](PeerId id) => id._value;

        public static BasePeerId FromBytes(byte[] bytes)
        {
            try
            {
                Digest multihash = Digest.Decode(bytes);

                if (multihash.Code == (int)HashCodes.Identity)
                {
                    if (multihash.DigestBytes.Length == MARSHALLED_ED225519_PUBLIC_KEY_LENGTH)
                        return new Ed25519PeerId(multihash);
                    else if (multihash.DigestBytes.Length == MARSHALLED_SECP256K1_PUBLIC_KEY_LENGTH)
                        return new Secp256k1PeerId(multihash);
                }

                if (multihash.Code == (int)HashCodes.SHA256)
                    return new RSAPeerId(multihash);
            }
            catch
            {
                return PeerId.FromCID(CID.Decode(bytes));
            }

            throw new Exception("Supplied PeerID CID is invalid");

        }

        private static BasePeerId FromCID(CID cid)
        {
            if (cid.Multihash == null || (cid.Version == 1 && cid.Code != LIBP2P_KEY_CODE))
                throw new Exception("Supplied PeerID CID is invalid");

            Digest multihash = cid.Multihash;

            if (multihash.Code == (int)HashCodes.SHA256)
                return new RSAPeerId(cid.Multihash);
            else if (multihash.Code == (int)HashCodes.Identity)
            {
                if (multihash.DigestBytes.Length == MARSHALLED_ED225519_PUBLIC_KEY_LENGTH)
                    return new Ed25519PeerId(cid.Multihash);
                else if (multihash.DigestBytes.Length == MARSHALLED_SECP256K1_PUBLIC_KEY_LENGTH)
                    return new Secp256k1PeerId(cid.Multihash);
            }

            throw new Exception("Supplied PeerID CID is invalid");
        }

        public static BasePeerId FromString(string str)
        {
            if (str.StartsWith("1") || str.StartsWith("Q"))
            {
                // identity hash ed25519/secp256k1 key or sha2-256 hash of
                // rsa public key - base58btc encoded either way
                var digest = Digest.Decode(new Base58Btc().BaseDecode($"z{str}"));

                if (str.StartsWith("12D"))
                    return new Ed25519PeerId(digest);
                else if (str.StartsWith("16U"))
                    return new Secp256k1PeerId(digest);
                else
                    return new RSAPeerId(digest);
            }

            byte [] bytes = Multibase.Decode(str, out MultibaseEncoding encoding);
            return PeerId.FromBytes(bytes);
        }
    }
}
