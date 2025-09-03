package com.ecareme.asuswebstorage.security;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class KeyStoreHelper {

    private static final String KEY_ALIAS = "MyKeyAlias";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";

    // 生成 KeyPair
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                ANDROID_KEYSTORE
        );

        KeyGenParameterSpec parameterSpec = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
        )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setUserAuthenticationRequired(false)
                .build();

        keyPairGenerator.initialize(parameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    // 取得已存在 KeyPair
    public static KeyPair getKeyPair() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        if (keyStore.containsAlias(KEY_ALIAS)) {
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
            return new KeyPair(entry.getCertificate().getPublicKey(), entry.getPrivateKey());
        } else {
            return null;
        }
    }

    // 用私鑰簽名資料
    public static String signData(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes("UTF-8"));
        byte[] signedBytes = signature.sign();
        return Base64.encodeToString(signedBytes, Base64.NO_WRAP);
    }

    // 取得公鑰
    public static String getPublicKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        KeyStore.Entry entry = keyStore.getEntry(KEY_ALIAS, null);
        if (entry instanceof KeyStore.PrivateKeyEntry) {
            PublicKey publicKey = ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey();
            // 轉成 Base64 方便印出或傳到 server
            return Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
        } else {
            throw new Exception("No key found under alias: " + KEY_ALIAS);
        }
    }

    // 取得簽章
    public static String getSignature(String data) throws Exception {
        KeyPair keyPair = getKeyPair();
        if (keyPair == null) {
            keyPair = generateKeyPair();
        }
        return signData(data, keyPair.getPrivate());
    }
}
