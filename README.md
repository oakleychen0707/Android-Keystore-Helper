# Android-Keystore-Helper
一個簡單的 Android Keystore 範例，示範如何在 Android KeyStore 中產生、保存並使用 RSA 金鑰進行簽章。

## 此專案提供以下功能：

- 在 Android KeyStore 中產生 RSA KeyPair（公鑰 / 私鑰）。
- 讀取已存在的 KeyPair。
- 使用私鑰對資料進行 SHA256withRSA 簽名。
- 取得公鑰並以 Base64 輸出，方便上傳至伺服器或進行驗證。
- 封裝 getSignature() 方法，簡化簽章流程。

## 主要程式碼

```KeyStoreHelper.java```

```java
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
```

## 使用方法
### 1. 產生或取得 KeyPair

```java
KeyPair keyPair = KeyStoreHelper.getKeyPair();
if (keyPair == null) {
    keyPair = KeyStoreHelper.generateKeyPair();
}
```

### 2. 對資料進行簽名

```java
String data = "Hello Keystore!";
String signature = KeyStoreHelper.signData(data, keyPair.getPrivate());

System.out.println("簽章結果: " + signature);
```

### 3. 取得公鑰 (Base64)

```java
String publicKeyBase64 = KeyStoreHelper.getPublicKey();
System.out.println("公鑰(Base64): " + publicKeyBase64);
```

### 4. 使用封裝的簡化方法

```java
String data = "Hello World";
String signature = KeyStoreHelper.getSignature(data);
System.out.println("Signature: " + signature);
```

## 應用情境

- 在 登入流程 中，App 可使用私鑰簽名伺服器給的 nonce，再由伺服器用對應的公鑰驗證，確保請求來自合法裝置。
- 在需要 敏感資料驗證（例如防止 API 被偽造呼叫）的場景，可搭配 Keystore 強化安全性。

## 注意事項

- 金鑰存放於 Android KeyStore，即使 App 被反編譯，也無法直接取得私鑰。
- 本範例使用 RSA + SHA256withRSA，若有更高效能需求，可改用 EC (Elliptic Curve) 演算法。
- 在高安全性需求下，可設定 ```.setUserAuthenticationRequired(true)```，強制使用者通過 PIN / 指紋才能使用私鑰。

## 模擬 Server 驗證流程

在真實情境中，App 會使用私鑰對伺服器給的 nonce 或資料做簽章，
伺服器只需要 公鑰 就能驗證這個簽章是否正確，確認請求來自合法的 App/裝置。

以下是一個簡單的 Java 伺服器端驗證範例：
- 將 App 產生的 公鑰 (Base64) 貼到 ```publicKeyB64```
- 將 App 產生的 簽章 (Base64) 貼到 ```signatureB64```
- 將原始資料（例如伺服器送出的 nonce）放入 ```data```

程式會輸出簽章是否有效 ✅❌

```java
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SignatureVerifier {

    public static boolean verifySignature(String publicKeyBase64, String signatureBase64, String data) {
        try {
            // 1. Base64 轉公鑰
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(spec);

            // 2. Base64 轉簽名
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

            // 3. 驗證簽名
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(data.getBytes("UTF-8"));

            return sig.verify(signatureBytes);

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        String publicKeyB64 = "你的公鑰";   // 公鑰
        String signatureB64 = "你的簽名";   // 簽名
        String data = "abc123"; // nonce

        boolean valid = verifySignature(publicKeyB64, signatureB64, data);
        System.out.println(valid ? "Signature is valid ✅" : "Signature is invalid ❌");
    }
}
```

## 結語

本專案示範了如何使用 Android Keystore 產生並管理 RSA 金鑰，並透過私鑰進行簽章、公鑰進行驗證。
這種機制能有效避免私鑰外洩，確保只有合法的 App/裝置能對伺服器的挑戰字串 (nonce) 進行簽名回應。

透過這樣的設計，可以：

- 強化 API 呼叫驗證，避免被竄改或偽造請求
- 提升 使用者登入 / 裝置綁定 的安全性
- 建立更完整的 雙向信任 (mutual trust) 機制

這是一個簡單的範例，實務上還可以結合 Play Integrity API、證書釘選 (Certificate Pinning)、安全通道 (TLS/HTTPS) 等技術，打造更全面的防護
