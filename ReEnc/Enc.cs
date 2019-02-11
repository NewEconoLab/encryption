using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using ThinNeo;

namespace ReEnc
{
    public class UmbralCapsule
    {
        public ThinNeo.Cryptography.ECC.ECPoint point_e;
        public ThinNeo.Cryptography.ECC.ECPoint point_v;
        public System.Numerics.BigInteger bn_sig;
    }
    public class UmbralPrivateKey
    {
        private UmbralPrivateKey()
        {

        }
        public System.Numerics.BigInteger key
        {
            get;
            private set;
        }
        public ThinNeo.Cryptography.ECC.ECCurve curve => ThinNeo.Cryptography.ECC.ECCurve.Secp256r1;
        public static UmbralPrivateKey GenRandomPrikey()
        {
            UmbralPrivateKey k = new UmbralPrivateKey();
            k.key = Helper_BigInt.NextBigInteger(k.curve.N.GetBitLength());
            return k;
        }
        public byte[] ToBytes()
        {
            var value = key.ToByteArray(true, true);

            return value;
        }
        public UmbralPublicKey GetPublicKey()
        {
            UmbralPublicKey pkey = new UmbralPublicKey(curve.G * this.key);
            return pkey;
        }
        public static UmbralPrivateKey Parse(byte[] data)
        {
            UmbralPrivateKey k = new UmbralPrivateKey();
            BigInteger _key = new BigInteger(data.Reverse().Concat(new byte[] { 0 }).ToArray());
            k.key = _key;
            return k;
        }
    }
    public class UmbralPublicKey
    {
        public UmbralPublicKey(ThinNeo.Cryptography.ECC.ECPoint point)
        {
            this.point = point;
        }
        public ThinNeo.Cryptography.ECC.ECPoint point
        {
            get;
            private set;
        }
        public ThinNeo.Cryptography.ECC.ECCurve curve => ThinNeo.Cryptography.ECC.ECCurve.Secp256r1;
        public byte[] ToBytes()
        {
            return this.point.EncodePoint(true);
        }
        public UmbralPublicKey Parse(byte[] data)
        {
            var point = ThinNeo.Cryptography.ECC.ECPoint.FromBytes(data, ThinNeo.Cryptography.ECC.ECCurve.Secp256r1);
            return new UmbralPublicKey(point);
        }
    }
    public class Enc
    {
        static ThinNeo.Cryptography.ECC.ECPoint kdf(ThinNeo.Cryptography.ECC.ECPoint point)
        {
            return point;
        }
        static System.Numerics.BigInteger hash_to_curvebn(params UmbralPublicKey[] keys)
        {
            IEnumerable<byte> bytes = keys[0].ToBytes();
            for(var i=1;i<keys.Length;i++)
            {
                bytes = bytes.Concat(keys[i].ToBytes());
            }
            var hash = ThinNeo.Helper.CalcSha256(bytes.ToArray());
            var h = new System.Numerics.BigInteger(hash.Concat(new byte[] { 0 }).ToArray());

            return h;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="publickey">公钥</param>
        /// <param name="plaintext">原文</param>
        /// <param name="capsule">胶囊，一揽子信息</param>
        /// <param name="ciphertext">原文</param>
        /// <returns></returns>
        public static bool Umbral_Encrypt(UmbralPublicKey publickey, byte[] plaintext,
            out UmbralCapsule capsule, out byte[] ciphertext)
        {
            capsule = null;
            ciphertext = null;


            //            g = params.g
            var g = publickey.curve.G;
            //priv_r = CurveBN.gen_rand(params.curve)
            var priv_r = UmbralPrivateKey.GenRandomPrikey();
            //    pub_r = priv_r * g  # type: Any
            var pub_r = priv_r.GetPublicKey();
            //    priv_u = CurveBN.gen_rand(params.curve)
            var priv_u = UmbralPrivateKey.GenRandomPrikey();

            //    pub_u = priv_u * g  # type: Any
            var pub_u = priv_u.GetPublicKey();

            //    h = hash_to_curvebn(pub_r, pub_u, params=params)
            var h = hash_to_curvebn(pub_r, pub_u);

            var s = priv_u.key + priv_r.key * h;
            //    s = priv_u + (priv_r * h)
            //这就是做了个签名嘛 ，pub_r 和 pub_u 按照bytearray连接起来，作为message,并算个hash，再编码成一个bigint h
            // s*g= priv_u*g+(priv_r*g*h)=pub_r+pub_u*h
            // 相当于用priv_u 和 priv_r双签名，pub_r 和 pub_u 双验签
            // if(pub_r+pub_u*h==s) 来判断胶囊和h是否匹配


            //    shared_key = (priv_r + priv_u) * alice_pubkey.point_key  # type: Any
            // shared_key 是个point，严格来说是个公钥
            ThinNeo.Cryptography.ECC.ECPoint shared_pubkey = publickey.point * (priv_r.key + priv_u.key);
            //# Key to be used for symmetric encryption
            ThinNeo.Cryptography.ECC.ECPoint key = kdf(shared_pubkey); //kdf 作不作都不影响这个算法,这个kdf函数只是走个过场

            capsule = new UmbralCapsule();
            capsule.point_e = pub_r.point;
            capsule.point_v = pub_u.point;
            capsule.bn_sig = s;
            //return key, Capsule(point_e = pub_r, point_v = pub_u, bn_sig = s, params=params)


            //核心加密逻辑
            //sharedkey =  publickey * (priv_r+priv_u);

            //核心解密逻辑
            //sharedkey =  privatekey * (pub_r+pub_u) ;

            //核心委托重加密逻辑 
            //d = hash_to_curvebn(precursor,
            //        bob_pubkey_point,
            //        dh_point,
            //        bytes(constants.NON_INTERACTIVE),
            //            params=params)
            //用d作为key，用bob的prikey可以得到这个key

            //加密时
            //precursor = r.G
            //bob_pubkey
            //dh_point = r.bob_pubkey

            //解密时
            //precursor = 传来
            //bob_pubkey
            //dh_point = bob_prikey.precursor

            //令rk = alicekey*(~d)
            //则sharedkey = alicekey*(pub_r+pub_u)
            //= alicekey * d * (~d) * (pub_r + pub_u);
            //= rk * d *(pub_r +pub_u)
            //= d * (pub_r*rk + pub_u*rk)

            //从publickey -> 转移委托给 publickeybob
            //可以得到一个publickeybob - publickey 的点 N

            //(h * e_prime) + v_prime:
            //所以sharedkey = (publickeybob - N)*(priv_r+priv_u) 
            //              = (privatekeybob.G *(priv_r+priv_u) - N*(priv_r +priv_u)
            // sharedkey    = privatekeybob*(pub_r+pub_u) - N*priv_r - N*priv_u
            //
            //
            //核心加密逻辑

            return false;
        }
    }
}
