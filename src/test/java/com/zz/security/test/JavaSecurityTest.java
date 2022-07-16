package com.zz.security.test;

import com.zz.security.JavaSecurity;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.RandomUtils;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.Cipher;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class JavaSecurityTest {

    @Test
    public void test_aes() throws Exception {
        byte[] key = JavaSecurity.genKey(256, "AES");

        byte[] content = RandomUtils.nextBytes(100);
        byte[] cipher = JavaSecurity.aesEncrypt(key, content);
        byte[] plain = JavaSecurity.aesDecrypt(key, cipher);

        Assert.assertArrayEquals(content, plain);
        Assert.assertEquals(cipher.length, plain.length + 16 - (plain.length % 16));

        content = RandomUtils.nextBytes(32);
        cipher = JavaSecurity.aes(key, content, null, "AES/ECB/NoPadding", Cipher.ENCRYPT_MODE);
        plain = JavaSecurity.aes(key, cipher, null, "AES/ECB/NoPadding", Cipher.DECRYPT_MODE);

        Assert.assertArrayEquals(content, plain);
        Assert.assertEquals(cipher.length, plain.length);
    }

    @Test
    public void test_gcm() throws Exception {
        byte[] key = JavaSecurity.genKey(256, "AES");
        byte[] nonce = RandomUtils.nextBytes(12);

        byte[] content = RandomUtils.nextBytes(125);
        byte[] cipher = JavaSecurity.gcmEncrypt(key, content, nonce);
        byte[] plain = JavaSecurity.gcmDecrypt(key, cipher, nonce);

        Assert.assertArrayEquals(content, plain);
        Assert.assertEquals(cipher.length, plain.length + 16);
    }

    @Test
    public void test_rsa() throws Exception {
        KeyPair keyPair = JavaSecurity.genKeyPair(2048, "RSA");
        byte[] privateKey = keyPair.getPrivate().getEncoded();
        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] content = RandomUtils.nextBytes(100);

        byte[] cipher = JavaSecurity.rsaEncrypt(publicKey, content);
        byte[] plain = JavaSecurity.rsaDecrypt(privateKey, cipher);

        Assert.assertArrayEquals(content, plain);

        byte[] sign = JavaSecurity.rsaSign(privateKey, content);
        boolean verify = JavaSecurity.rsaVerify(publicKey, content, sign);
        Assert.assertTrue(verify);
    }

    @Test
    public void test_ec() throws Exception {
        KeyPair keyPair = JavaSecurity.genKeyPair(256, "EC");
        byte[] privateKey = keyPair.getPrivate().getEncoded();
        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] content = RandomUtils.nextBytes(100);

        byte[] cipher = JavaSecurity.eccEncrypt(publicKey, content);
        byte[] plain = JavaSecurity.eccDecrypt(privateKey, cipher);

        Assert.assertArrayEquals(content, plain);

        byte[] sign = JavaSecurity.eccSign(privateKey, content);
        boolean verify = JavaSecurity.eccVerify(publicKey, content, sign);
        Assert.assertTrue(verify);
    }

    @Test
    public void test_dsa() throws Exception {
        KeyPair keyPair = JavaSecurity.genKeyPair(2048, "DSA");
        byte[] content = RandomUtils.nextBytes(100);

        byte[] sign = JavaSecurity.sign(keyPair.getPrivate(), content, null, "SHA256WithDSA");
        boolean verify = JavaSecurity.verify(keyPair.getPublic(), content, sign, null, "SHA256WithDSA");
        Assert.assertTrue(verify);
    }

    @Test
    public void test_ecdh() throws Exception {
        KeyPair keyPair1 = JavaSecurity.genKeyPair(256, "EC");
        KeyPair keyPair2 = JavaSecurity.genKeyPair(256, "EC");
        byte[] key1 = JavaSecurity.ecDhAgreeKey(keyPair1.getPrivate(), keyPair2.getPublic());
        byte[] key2 = JavaSecurity.ecDhAgreeKey(keyPair2.getPrivate(), keyPair1.getPublic());

        Assert.assertArrayEquals(key1, key2);

        byte[] content = RandomUtils.nextBytes(100);
        byte[] cipher = JavaSecurity.aesEncrypt(key1, content);
        byte[] plain = JavaSecurity.aesDecrypt(key2, cipher);

        Assert.assertArrayEquals(content, plain);
        Assert.assertEquals(cipher.length, plain.length + 16 - (plain.length % 16));
    }

    @Test
    public void test_hmac() throws Exception {
        byte[] key = JavaSecurity.genKey(256, "AES");
        byte[] content = RandomUtils.nextBytes(100);
        byte[] mac = JavaSecurity.hmac(key, content, "HMACSHA256");
        Assert.assertEquals(mac.length, 32);

        mac = JavaSecurity.hmac(key, content, "HMACMD5");
        Assert.assertEquals(mac.length, 16);
    }

    @Test
    public void test_hash() throws Exception {
        byte[] content = RandomUtils.nextBytes(100);

        byte[] hash = JavaSecurity.hash(content, "MD5");
        Assert.assertEquals(hash.length, 16);

        hash = JavaSecurity.hash(content, "SHA256");
        Assert.assertEquals(hash.length, 32);
    }

    @Test
    public void test_cert() throws Exception {
        Path certPath = Paths.get(getClass().getClassLoader().getResource("cert.crt").toURI());
        String rsaKeyPemContent = new String(Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource("rsa.key").toURI())));

        X509Certificate cert1 = JavaSecurity.readCertificate(Files.newInputStream(certPath));
        X509Certificate cert2 = JavaSecurity.readCertificate(new String(Files.readAllBytes(certPath)));

        Assert.assertEquals(cert1.getSerialNumber(), cert2.getSerialNumber());

        PublicKey publicKey = cert1.getPublicKey();
        KeyPair keyPair = JavaSecurity.readKeyPairFromPKCS1Pem(rsaKeyPemContent);
        Assert.assertArrayEquals(publicKey.getEncoded(), keyPair.getPublic().getEncoded());

        String cert3 = JavaSecurity.writeCertificate(cert1);
        Assert.assertEquals(cert3, new String(Files.readAllBytes(certPath)));
    }

    @Test
    public void test_parse_key_pair() throws Exception {
        byte[] content = RandomUtils.nextBytes(100);
        String rsaKeyPemContent = new String(Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource("rsa.key").toURI())));
        String eccKeyPemContent = new String(Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource("ecc.key").toURI())));
        String rsaPkcs8KeyPemContent = new String(Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource("rsa_pkcs8.key").toURI())));

        KeyPair keyPair1 = JavaSecurity.readKeyPairFromPKCS1Pem(rsaKeyPemContent);
        PrivateKey privateKey1 = keyPair1.getPrivate();
        PublicKey publicKey1 = keyPair1.getPublic();
        byte[] cipher = JavaSecurity.cipher(publicKey1, content, null, "RSA", Cipher.ENCRYPT_MODE);
        byte[] plain = JavaSecurity.cipher(privateKey1, cipher, null, "RSA", Cipher.DECRYPT_MODE);

        Assert.assertArrayEquals(content, plain);

        byte[] sign = JavaSecurity.rsaSign(privateKey1.getEncoded(), content);
        boolean verify = JavaSecurity.rsaVerify(publicKey1.getEncoded(), content, sign);
        Assert.assertTrue(verify);

        KeyPair keyPair2 = JavaSecurity.readKeyPairFromPKCS1Pem(eccKeyPemContent);
        PrivateKey privateKey2 = keyPair2.getPrivate();
        PublicKey publicKey2 = keyPair2.getPublic();

        cipher = JavaSecurity.eccEncrypt(publicKey2.getEncoded(), content);
        plain = JavaSecurity.eccDecrypt(privateKey2.getEncoded(), cipher);

        Assert.assertArrayEquals(content, plain);

        sign = JavaSecurity.eccSign(privateKey2.getEncoded(), content);
        verify = JavaSecurity.eccVerify(publicKey2.getEncoded(), content, sign);
        Assert.assertTrue(verify);

        PrivateKey privateKey3 = JavaSecurity.readPrivateKeyFromPKCS8Pem(rsaPkcs8KeyPemContent);
        PublicKey publicKey3 = JavaSecurity.getFromPrivateKey(privateKey3);

        cipher = JavaSecurity.rsaEncrypt(publicKey3.getEncoded(), content);
        plain = JavaSecurity.rsaDecrypt(privateKey3.getEncoded(), cipher);

        Assert.assertArrayEquals(content, plain);

        sign = JavaSecurity.rsaSign(privateKey3.getEncoded(), content);
        verify = JavaSecurity.rsaVerify(publicKey3.getEncoded(), content, sign);
        Assert.assertTrue(verify);
    }

    @Test
    public void test_parse_key() throws Exception {
        byte[] content = RandomUtils.nextBytes(100);
        String rsaKeyPemContent = new String(Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource("rsa.key").toURI())));
        String eccKeyPemContent = new String(Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource("ecc.key").toURI())));
        String rsaPkcs8KeyPemContent = new String(Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource("rsa_pkcs8.key").toURI())));

        rsaKeyPemContent = rsaKeyPemContent.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        rsaKeyPemContent = rsaKeyPemContent.replace("-----END RSA PRIVATE KEY-----", "");

        eccKeyPemContent = eccKeyPemContent.replace("-----BEGIN EC PRIVATE KEY-----", "");
        eccKeyPemContent = eccKeyPemContent.replace("-----END EC PRIVATE KEY-----", "");

        rsaPkcs8KeyPemContent = rsaPkcs8KeyPemContent.replace("-----BEGIN PRIVATE KEY-----", "");
        rsaPkcs8KeyPemContent = rsaPkcs8KeyPemContent.replace("-----END PRIVATE KEY-----", "");

        PrivateKey privateKey1 = JavaSecurity.parseOpensslRsaPrivateKey(Base64.decodeBase64(rsaKeyPemContent));
        PrivateKey privateKey2 = JavaSecurity.parseOpensslEcPrivateKey(Base64.decodeBase64(eccKeyPemContent));
        PrivateKey privateKey3 = JavaSecurity.getPrivate(Base64.decodeBase64(rsaPkcs8KeyPemContent), "RSA");

        KeyPair keyPair1 = JavaSecurity.parseOpensslRsaKeyPair(Base64.decodeBase64(rsaKeyPemContent));
        KeyPair keyPair2 = JavaSecurity.parseOpensslEcKeyPair(Base64.decodeBase64(eccKeyPemContent));

        PublicKey publicKey1 = JavaSecurity.getFromPrivateKey(privateKey1);
        PublicKey publicKey2 = JavaSecurity.getFromPrivateKey(privateKey2);
        PublicKey publicKey3 = JavaSecurity.getFromPrivateKey(privateKey3);

        Assert.assertArrayEquals(keyPair1.getPrivate().getEncoded(), privateKey1.getEncoded());
        Assert.assertArrayEquals(keyPair2.getPrivate().getEncoded(), privateKey2.getEncoded());

        byte[] sign = JavaSecurity.rsaSign(privateKey1.getEncoded(), content);
        boolean verify = JavaSecurity.rsaVerify(publicKey1.getEncoded(), content, sign);
        Assert.assertTrue(verify);

        sign = JavaSecurity.eccSign(privateKey2.getEncoded(), content);
        verify = JavaSecurity.eccVerify(publicKey2.getEncoded(), content, sign);
        Assert.assertTrue(verify);

        sign = JavaSecurity.rsaSign(privateKey3.getEncoded(), content);
        verify = JavaSecurity.rsaVerify(publicKey3.getEncoded(), content, sign);
        Assert.assertTrue(verify);
    }

    @Test
    public void test_sm() throws Exception {
        KeyPair sm2KeyPair = JavaSecurity.genSm2KeyPair();
        byte[] privateKey = sm2KeyPair.getPrivate().getEncoded();
        byte[] publicKey = sm2KeyPair.getPublic().getEncoded();
        byte[] content = RandomUtils.nextBytes(100);

        byte[] cipher = JavaSecurity.eccEncrypt(publicKey, content);
        byte[] plain = JavaSecurity.eccDecrypt(privateKey, cipher);

        Assert.assertArrayEquals(content, plain);

        byte[] sign = JavaSecurity.eccSign(privateKey, content);
        boolean verify = JavaSecurity.eccVerify(publicKey, content, sign);
        Assert.assertTrue(verify);

        byte[] sm4Key = JavaSecurity.genKey(128, "SM4");
        content = RandomUtils.nextBytes(100);
        byte[] iv = RandomUtils.nextBytes(16);
        cipher = JavaSecurity.aes(sm4Key, content, iv, "SM4/CBC/PKCS5Padding", Cipher.ENCRYPT_MODE);
        plain = JavaSecurity.aes(sm4Key, cipher, iv, "SM4/CBC/PKCS5Padding", Cipher.DECRYPT_MODE);

        Assert.assertArrayEquals(content, plain);
        Assert.assertEquals(cipher.length, plain.length + 16 - (plain.length % 16));

        byte[] hash = JavaSecurity.sm3(content);
        Assert.assertEquals(hash.length, 32);
    }

    @Test
    public void test_pbkdf() throws Exception {
        String password = RandomStringUtils.random(10);
        byte[] salt = RandomUtils.nextBytes(12);
        byte[] cipher = JavaSecurity.pbkdf(password.toCharArray(), salt);
        Assert.assertEquals(cipher.length, 32);

        cipher = JavaSecurity.pbkdf(password.toCharArray(), salt, 1024, 128, "PBKDF2WithHmacSHA1");
        Assert.assertEquals(cipher.length, 16);
    }
}
