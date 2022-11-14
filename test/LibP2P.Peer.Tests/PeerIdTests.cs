using System;
using LibP2P.Peer.Interfaces;
using Multiformats.Base;
using NUnit.Framework;

namespace LibP2P.Peer.Tests
{
    public class PeerIdTests
    {
        

        [Test(Description = "create a new id from multihash")]
        public void CreateNewIdFromMultihash()
        {
            var decoded = new Base58Btc().BaseDecode("12D3KooWbtp1AcgweFSArD7dbKWYpAr8MZR1tofwNwLFLjeNGLWa");
            var id = PeerId.FromBytes(decoded);
            //Assert.That(id.equals(buf)).to.be.true()
        }

        [Test(Description = "parses a v1 CID with the libp2p-key codec")]
        public void ParsesCIDv1WithLibP2PKeyCodec()
        {
            string str = "bafzaajaiaejca24q7uhr7adt3rtai4ixtn2r3q72kccwvwzg6wnfetwqyvrs5n2d";
            var id = PeerId.FromString(str);

            Assert.That(id.Type, Is.EqualTo(PeerIdType.Ed25519));
            Assert.That(id.ToString(), Is.EqualTo("12D3KooWH4G2B3x5BZHH3j2ccMsBLhzR8u1uzrAQshg429xGFGPk"));
            Assert.That(id.ToCID().ToString(), Is.EqualTo("bafzaajaiaejca24q7uhr7adt3rtai4ixtn2r3q72kccwvwzg6wnfetwqyvrs5n2d"));
        }

        [Test(Description = "defaults to base58btc when stringifying")]
        public void DefaultsToBase58BtcWhenStringifying()
        {
            var decoded = Multibase.DecodeRaw(MultibaseEncoding.Base58Btc, "12D3KooWbtp1AcgweFSArD7dbKWYpAr8MZR1tofwNwLFLjeNGLWa");
            var id = PeerId.FromBytes(decoded);
            Assert.That(id.ToString(), Is.EqualTo("12D3KooWbtp1AcgweFSArD7dbKWYpAr8MZR1tofwNwLFLjeNGLWa"));
        }

        [Test(Description ="turns into a CID")]
        public void TurnsIntoACID()
        {
            byte[] buf = Multibase.DecodeRaw(MultibaseEncoding.Base58Btc, "12D3KooWbtp1AcgweFSArD7dbKWYpAr8MZR1tofwNwLFLjeNGLWa");
            var id = PeerId.FromBytes(buf);
            Assert.That(id.ToCID().ToString(), Is.EqualTo("bafzaajaiaejcda3tmul6p2537j5upxpjgz3jabbzxqrjqvhhfnthtnezvwibizjh"));
        }

        [Test(Description ="equals a byte[]")]
        public void EqualsAByteArray()
        {
            byte[] buf = Multibase.DecodeRaw(MultibaseEncoding.Base58Btc, "12D3KooWbtp1AcgweFSArD7dbKWYpAr8MZR1tofwNwLFLjeNGLWa");
            var id = PeerId.FromBytes(buf);
            Assert.That(id.Equals(buf));
        }

        [Test(Description = "equals a PeerId")]
        public void EqualsAPeerId()
        {
            byte[] buf = Multibase.DecodeRaw(MultibaseEncoding.Base58Btc, "12D3KooWbtp1AcgweFSArD7dbKWYpAr8MZR1tofwNwLFLjeNGLWa");
            var id = PeerId.FromBytes(buf);
            Assert.That(id.Equals(PeerId.FromBytes(buf)));
        }

        [Test(Description = "parses a PeerId as RSA")]
        public void ParsesPeerIdAsRSA()
        {
            var id = PeerId.FromString("QmZHBBrcBtDk7yVzcNUDJBJsZnVGtPHzpTzu16J7Sk6hbp");
            Assert.That(id.GetType(), Is.EqualTo(typeof(RSAPeerId)));
        }

        [Test(Description = "parses a PeerId as secp256k1")]
        public void ParsesPeerIdAsSecp256k1()
        {
            var id = PeerId.FromString("16Uiu2HAkxSnqYGDU5iZTQrZyAcQDQHKrZqSNPBmKFifEagS2XfrL");
            Assert.That(id.GetType(), Is.EqualTo(typeof(Secp256k1PeerId)));
        }

        [Test(Description = "decodes a PeerId as Ed25519")]
        public void DecodesPeerIdAsEd25519()
        {
            byte[] buf = Multibase.DecodeRaw(MultibaseEncoding.Base58Btc, "12D3KooWbtp1AcgweFSArD7dbKWYpAr8MZR1tofwNwLFLjeNGLWa");
            var id = PeerId.FromBytes(buf);
            Assert.That(id.GetType(), Is.EqualTo(typeof(Ed25519PeerId)));
        }

        [Test(Description = "decodes a PeerId as RSA")]
        public void DecodesPeerIdAsRSA()
        {
            byte[] buf = Multibase.DecodeRaw(MultibaseEncoding.Base58Btc, "QmZHBBrcBtDk7yVzcNUDJBJsZnVGtPHzpTzu16J7Sk6hbp");
            var id = PeerId.FromBytes(buf);
            Assert.That(id.GetType(), Is.EqualTo(typeof(RSAPeerId)));
        }

        [Test(Description = "decodes a PeerId as secp256k1")]
        public void DecodesPeerIdAsSecp256k1()
        {
            byte[] buf = Multibase.DecodeRaw(MultibaseEncoding.Base58Btc, "16Uiu2HAkxSnqYGDU5iZTQrZyAcQDQHKrZqSNPBmKFifEagS2XfrL");
            var id = PeerId.FromBytes(buf);
            Assert.That(id.GetType(), Is.EqualTo(typeof(Secp256k1PeerId)));
        }

        [Test(Description = "ToJSON()")]
        public void ToJSON()
        {
            byte[] buf = Multibase.DecodeRaw(MultibaseEncoding.Base58Btc, "16Uiu2HAkxSnqYGDU5iZTQrZyAcQDQHKrZqSNPBmKFifEagS2XfrL");
            var id = PeerId.FromBytes(buf);
            string json = id.ToJSON();
            var reconst = Newtonsoft.Json.JsonConvert.DeserializeObject<PeerIdRecord>(json);
            Assert.That(reconst.Type, Is.EqualTo((int)id.Type));
            Assert.That(reconst.Hash, Is.EqualTo(id.Multihash.Bytes));
            Assert.That(reconst.PrivateKey, Is.EqualTo(id.PrivateKey));
            Assert.That(reconst.PublicKey, Is.EqualTo(id.PublicKey));
        }
    }
}
