package com.zz.security;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.*;
import java.util.Date;

public class JavaSecurity {

    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final byte[] DEFAULT_IV = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    public static byte[] aesEncrypt(byte[] key, byte[] plain) throws Exception {
        return aes(key, plain, DEFAULT_IV, "AES/CBC/PKCS5Padding", Cipher.ENCRYPT_MODE);
    }

    public static byte[] aesDecrypt(byte[] key, byte[] cipher) throws Exception {
        return aes(key, cipher, DEFAULT_IV, "AES/CBC/PKCS5Padding", Cipher.DECRYPT_MODE);
    }

    public static byte[] rsaEncrypt(byte[] publicKey, byte[] plain) throws Exception {
        PublicKey key = getPublic(publicKey, "RSA");
        return cipher(key, plain, null, "RSA", Cipher.ENCRYPT_MODE);
    }

    public static byte[] rsaDecrypt(byte[] privateKey, byte[] cipher) throws Exception {
        PrivateKey key = getPrivate(privateKey, "RSA");
        return cipher(key, cipher, null, "RSA", Cipher.DECRYPT_MODE);
    }

    public static byte[] eccEncrypt(byte[] publicKey, byte[] plain) throws Exception {
        PublicKey key = getPublic(publicKey, "EC");
        return cipher(key, plain, null, "ECIES", Cipher.ENCRYPT_MODE);
    }

    public static byte[] eccDecrypt(byte[] privateKey, byte[] cipher) throws Exception {
        PrivateKey key = getPrivate(privateKey, "EC");
        return cipher(key, cipher, null, "ECIES", Cipher.DECRYPT_MODE);
    }

    public static byte[] gcmEncrypt(byte[] key, byte[] plain, byte[] nonce) throws Exception {
        return gcm(key, plain, new GCMParameterSpec(128, nonce), Cipher.ENCRYPT_MODE, null);
    }

    public static byte[] gcmDecrypt(byte[] key, byte[] cipher, byte[] nonce) throws Exception {
        return gcm(key, cipher, new GCMParameterSpec(128, nonce), Cipher.DECRYPT_MODE, null);
    }

    public static byte[] aes(byte[] key, byte[] content, byte[] iv, String padding, int encryptMode) throws Exception {
        Key secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec spec = null;
        if (iv != null) {
            spec = new IvParameterSpec(iv);
        }
        return cipher(secretKey, content, spec, padding, encryptMode);
    }

    public static byte[] gcm(byte[] key, byte[] content, GCMParameterSpec spec, int encryptMode, byte[] associatedData) throws Exception {
        Key secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", PROVIDER);
        cipher.init(encryptMode, secretKey, spec);
        if (associatedData != null) {
            cipher.updateAAD(associatedData);
        }
        return cipher.doFinal(content);
    }

    public static byte[] rsaSign(byte[] privateKey, byte[] plain) throws Exception {
        PrivateKey key = getPrivate(privateKey, "RSA");
        return sign(key, plain, null, "SHA256WithRSA");
    }

    public static boolean rsaVerify(byte[] publicKey, byte[] plain, byte[] sign) throws Exception {
        PublicKey key = getPublic(publicKey, "RSA");
        return verify(key, plain, sign, null, "SHA256WithRSA");
    }

    public static byte[] eccSign(byte[] privateKey, byte[] plain) throws Exception {
        PrivateKey key = getPrivate(privateKey, "EC");
        return sign(key, plain, null, "SHA256WithECDSA");
    }

    public static boolean eccVerify(byte[] publicKey, byte[] plain, byte[] sign) throws Exception {
        PublicKey key = getPublic(publicKey, "EC");
        return verify(key, plain, sign, null, "SHA256WithECDSA");
    }

    public static byte[] sign(PrivateKey privateKey, byte[] plain, AlgorithmParameterSpec spec, String alg) throws Exception {
        Signature signature = Signature.getInstance(alg, PROVIDER);
        if (spec != null) {
            signature.setParameter(spec);
        }
        signature.initSign(privateKey);
        signature.update(plain);
        return signature.sign();
    }

    public static boolean verify(PublicKey publicKey, byte[] plain, byte[] sign, AlgorithmParameterSpec spec, String alg) throws Exception {
        Signature signature = Signature.getInstance(alg, PROVIDER);
        if (spec != null) {
            signature.setParameter(spec);
        }
        signature.initVerify(publicKey);
        signature.update(plain);
        return signature.verify(sign);
    }

    public static byte[] cipher(Key key, byte[] content, AlgorithmParameterSpec spec, String padding, int encryptMode) throws Exception {
        Cipher cipher = Cipher.getInstance(padding, PROVIDER);
        if (spec != null) {
            cipher.init(encryptMode, key, spec);
        } else {
            cipher.init(encryptMode, key);
        }
        return cipher.doFinal(content);
    }

    public static byte[] sm3(byte[] content) throws Exception {
        return hash(content, "SM3");
    }

    public static byte[] hash(byte[] content, String alg) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(alg, PROVIDER);
        return digest.digest(content);
    }

    public static byte[] hmac(byte[] key, byte[] content, String alg) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, alg);
        Mac mac = Mac.getInstance(alg, PROVIDER);
        mac.init(secretKey);
        return mac.doFinal(content);
    }

    public static byte[] ecDhAgreeKey(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("ECCDH", PROVIDER);
        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);
        SecretKey agreeKey = agreement.generateSecret("AES[256]");
        return agreeKey.getEncoded();
    }

    public static byte[] pbkdf(char[] password, byte[] salt) throws Exception {
        return pbkdf(password, salt, 1024, 256, "PBKDF2WithHmacSHA256");
    }

    public static byte[] pbkdf(char[] password, byte[] salt, int iterationCount, int keySize, String alg) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(alg, PROVIDER);
        KeySpec spec = new PBEKeySpec(password, salt, iterationCount, keySize);
        Key key = factory.generateSecret(spec);
        return key.getEncoded();
    }

    public static byte[] genKey(int keySize, String alg) throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance(alg, PROVIDER);
        gen.init(keySize, new SecureRandom());
        return gen.generateKey().getEncoded();
    }

    public static KeyPair genSm2KeyPair() throws Exception {
        return genEccKeyPair("sm2p256v1");
    }

    public static KeyPair genEccKeyPair(String curveName) throws Exception {
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        return genKeyPair(spec, "EC");
    }

    public static KeyPair genKeyPair(int keySize, String alg) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(alg, PROVIDER);
        gen.initialize(keySize, new SecureRandom());
        return gen.generateKeyPair();
    }

    public static KeyPair genKeyPair(AlgorithmParameterSpec spec, String alg) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(alg, PROVIDER);
        gen.initialize(spec, new SecureRandom());
        return gen.generateKeyPair();
    }

    /**
     * 从pem 文件中提取密钥对
     * 
     * @param pemContent 以 '-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN EC PRIVATE KEY-----' 开头
     */
    public static KeyPair readKeyPairFromPKCS1Pem(String pemContent) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemContent))) {
            Object parsed = pemParser.readObject();
            return new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) parsed);
        }
    }

    /**
     * 从openssl 私钥格式中获取密钥对
     *
     * @param pkcs1Key pem 文件去除 '----BEGIN RSA PRIVATE KEY----', '----END RSA PRIVATE KEY----' 的base64 decode
     */
    public static KeyPair parseOpensslRsaKeyPair(byte[] pkcs1Key) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", PROVIDER);
        RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(ASN1Sequence.fromByteArray(pkcs1Key));
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPrivateExponent());
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPublicExponent());
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * 从openssl 私钥格式中获取密钥对
     *
     * @param pkcs1Key pem 文件去除 '----BEGIN EC PRIVATE KEY----', '----END EC PRIVATE KEY----' 的base64 decode
     */
    public static KeyPair parseOpensslEcKeyPair(byte[] pkcs1Key) throws Exception {
        PublicKey publicKey = null;
        KeyFactory keyFactory = KeyFactory.getInstance("EC", PROVIDER);
        ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(ASN1Sequence.getInstance(pkcs1Key));
        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, ecPrivateKey.getParameters());
        PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(algId, ecPrivateKey);
        if (ecPrivateKey.getPublicKey() != null) {
            SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(algId, ecPrivateKey.getPublicKey().getBytes());
            publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded()));
        }
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
        return new KeyPair(publicKey, privateKey);
    }

    public static PublicKey getPublic(byte[] publicKey, String alg) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(alg, PROVIDER);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey);
        return keyFactory.generatePublic(spec);
    }

    public static PrivateKey getPrivate(byte[] privateKey, String alg) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(alg, PROVIDER);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey);
        return keyFactory.generatePrivate(spec);
    }

    /**
     * 从pem文件中获取 PKCS#8类型的RSA私钥
     *
     * @param pemContent 以 '-----BEGIN PRIVATE KEY-----' 开头
     */
    public static PrivateKey readPrivateKeyFromPKCS8Pem(String pemContent) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemContent))) {
            Object parsed = pemParser.readObject();
            return new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) parsed);
        }
    }

    /**
     * 获取RSA私钥
     * @param pkcs1Key pem 文件去除'-----BEGIN RSA PRIVATE KEY-----','-----ENC RSA PRIVATE KEY-----'的base64 decode
     */
    public static PrivateKey parseOpensslRsaPrivateKey(byte[] pkcs1Key) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", PROVIDER);
        RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(ASN1Sequence.getInstance(pkcs1Key));
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPrivateExponent());
        return keyFactory.generatePrivate(privateKeySpec);
    }

    /**
     * 获取EC私钥
     * @param pkcs1Key pem 文件去除'-----BEGIN EC PRIVATE KEY-----','-----ENC EC PRIVATE KEY-----'的base64 decode
     */
    public static PrivateKey parseOpensslEcPrivateKey(byte[] pkcs1Key) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("EC", PROVIDER);
        ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(ASN1Sequence.fromByteArray(pkcs1Key));
        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, ecPrivateKey.getParameters());
        PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(algId, ecPrivateKey);
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
    }

    /**
     * 从私钥中读取公钥，包括RSA，BCEC私钥
     * @param privateKey 私钥对象
     */
    public static PublicKey getFromPrivateKey(PrivateKey privateKey) throws Exception {
        if (privateKey instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) privateKey;
            RSAPublicKeySpec spec = new RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", PROVIDER);
            return keyFactory.generatePublic(spec);
        } else if (privateKey instanceof java.security.interfaces.RSAPrivateKey) {
            java.security.interfaces.RSAPrivateKey rsaPrivateKey = (java.security.interfaces.RSAPrivateKey) privateKey;
            RSAPublicKeySpec spec = new RSAPublicKeySpec(rsaPrivateKey.getModulus(), BigInteger.valueOf(65537));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", PROVIDER);
            return keyFactory.generatePublic(spec);
        } else if (privateKey instanceof BCECPrivateKey) {
            BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) privateKey;
            ECParameterSpec spec = bcecPrivateKey.getParameters();
            ECPoint q = spec.getG().multiply(bcecPrivateKey.getD());
            KeyFactory keyFactory = KeyFactory.getInstance("EC", PROVIDER);
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(q, spec);
            return keyFactory.generatePublic(pubSpec);
        }
        return null;
    }

    public static X509Certificate readCertificate(InputStream inputStream) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509", PROVIDER);
        return (X509Certificate) factory.generateCertificate(inputStream);
    }

    public static X509Certificate readCertificate(String pemContent) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemContent))) {
            X509CertificateHolder holder = (X509CertificateHolder) pemParser.readObject();
            return new JcaX509CertificateConverter().getCertificate(holder);
        }
    }

    public static String writeCertificate(X509Certificate certificate) throws Exception {
        StringWriter stringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        return stringWriter.toString();
    }

    public static X509Certificate createCertificate(Date notBefore, Date notAfter, String issuer,
            String subject, PrivateKey issuerPrivateKey, PublicKey subjectPublicKey) throws Exception {
        X500Name issuerName = new X500Name(issuer);
        X500Name subjectName = new X500Name(subject);

        X509v3CertificateBuilder certBuillder = new JcaX509v3CertificateBuilder(
                issuerName,
                BigInteger.valueOf(System.currentTimeMillis()),
                notBefore,
                notAfter,
                subjectName,
                subjectPublicKey);

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(issuerPrivateKey);

        return new JcaX509CertificateConverter().getCertificate(certBuillder.build(contentSigner));
    }
}
