package com.example.jeffrey.securestorageandroid

import android.content.Context
import android.os.Build
import android.os.Bundle
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.widget.Button
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import com.google.common.io.BaseEncoding
import com.google.crypto.tink.*
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.aead.AeadFactory
import com.google.crypto.tink.aead.AeadKeyTemplates
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.google.crypto.tink.signature.PublicKeySignFactory
import com.google.crypto.tink.signature.PublicKeyVerifyFactory
import com.google.crypto.tink.signature.SignatureKeyTemplates
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.security.auth.x500.X500Principal


class MainActivity : AppCompatActivity() {

    private val job = Job()
    private val ioScope = CoroutineScope(Dispatchers.IO + job)
    private val uiScope = CoroutineScope(Dispatchers.Main + job)

    private var keysetHandle: KeysetHandle? = null
    private var aeadPrimitive: Aead? = null

    companion object {
        private val LOGGER = LoggerFactory.getLogger(MainActivity::class.java)

        const val ANDROID_KEYSTORE:String = "AndroidKeyStore"

        const val INSTANCE_ID:String = "guid"
        const val INSTANCE_CREDENTIAL:String = "credential"

        const val SIGNING_KEYSET:String = "signingKeyset"

        const val CIPHER_PADDING_RSA_ECB:String = "RSA/ECB/PKCS1Padding"
        const val CIPHER_PADDING_AES_CBC:String = "AES/CBC/PKCS7Padding"
        const val CIPHER_PADDING_AES_GCM:String = "AES/GCM/NoPadding"

        const val IV_SEPARATOR = ":" // not used in base64 encoding table

        const val KEYSET_NAME = "my_keyset"
        const val MASTER_KEY_URI = "android-keystore://my_master_key_id"
        const val PREF_FILENAME = "my_pref_file"
    }

    init {
        val context = this
        ioScope.launch {
            try {
                TinkConfig.register()
                AeadConfig.register()

                // in-memory keyset without using any platform's keystore manager
                //keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM)
                //aeadPrimitive = AeadFactory.getPrimitive(keysetHandle)

                val keysetManager:AndroidKeysetManager? = AndroidKeysetManager.Builder()
                    .withSharedPref(context, KEYSET_NAME, PREF_FILENAME)
                    .withMasterKeyUri(MASTER_KEY_URI)
                    .withKeyTemplate(AeadKeyTemplates.AES256_GCM)
                    .build()

                keysetManager?.let {
                    keysetHandle = keysetManager.keysetHandle
                    aeadPrimitive = AeadFactory.getPrimitive(keysetHandle)
                }
            } catch (e:Exception) {
                LOGGER.error(e.message, e)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initUI()
    }

    private fun initUI() {
        val generateInstanceIdBtn = findViewById<Button>(R.id.generateInstanceIdBtn)
        generateInstanceIdBtn.setOnClickListener {
            ioScope.launch {
                generateInstanceId()
            }
        }

        val loadInstanceIdBtn = findViewById<Button>(R.id.loadInstanceIdBtn)
        loadInstanceIdBtn.setOnClickListener {
            ioScope.launch {
                loadInstanceId()
            }
        }

        val generateSecretRsaBtn = findViewById<Button>(R.id.generateSecretRsaBtn)
        generateSecretRsaBtn.setOnClickListener {
            ioScope.launch {
                generateSecretRSA(loadInstanceId())
            }
        }

        val loadSecretRsaBtn = findViewById<Button>(R.id.loadSecretRsaBtn)
        loadSecretRsaBtn.setOnClickListener {
            ioScope.launch {
                loadSecretRSA()
            }
        }

        val encryptRsaBtn = findViewById<Button>(R.id.encryptRsaBtn)
        encryptRsaBtn.setOnClickListener {
            ioScope.launch {
                encryptStringRsa()
            }
        }

        val decryptRsaBtn = findViewById<Button>(R.id.decryptRsaBtn)
        decryptRsaBtn.setOnClickListener {
            ioScope.launch {
                decryptStringRsa()
            }
        }

        val generateSecretAesBtn = findViewById<Button>(R.id.generateSecretAesBtn)
        generateSecretAesBtn.setOnClickListener {
            ioScope.launch {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                    generateSecretAES(loadInstanceId())
            }
        }

        val loadSecretAesBtn = findViewById<Button>(R.id.loadSecretAesBtn)
        loadSecretAesBtn.setOnClickListener {
            ioScope.launch {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                    loadSecretAES()
            }
        }

        val encryptAesBtn = findViewById<Button>(R.id.encryptAesBtn)
        encryptAesBtn.setOnClickListener {
            ioScope.launch {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                    encryptStringAes()
            }
        }

        val decryptAesBtn = findViewById<Button>(R.id.decryptAesBtn)
        decryptAesBtn.setOnClickListener {
            ioScope.launch {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                    decryptStringAes()
            }
        }

        val generateSigningKeysetEcdsaBtn = findViewById<Button>(R.id.generateSigningKeysetEcdsaBtn)
        generateSigningKeysetEcdsaBtn.setOnClickListener {
            ioScope.launch {
                generateSigningKeysetECDSA()
            }
        }

        val loadSigningKeysetEcdsaBtn = findViewById<Button>(R.id.loadSigningKeysetEcdsaBtn)
        loadSigningKeysetEcdsaBtn.setOnClickListener {
            ioScope.launch {
                loadSigningKeysetECDSA()
            }
        }

        val signMessageBtn = findViewById<Button>(R.id.signMessageBtn)
        signMessageBtn.setOnClickListener {
            ioScope.launch {
                signMessage()
            }
        }
    }

    private fun loadInstanceId():String {
        LOGGER.info("loadInstanceId")

        val sharedPref = this.getSharedPreferences(this.packageName, Context.MODE_PRIVATE)
        val instanceId:String? = sharedPref.getString(INSTANCE_ID, null)

        instanceId?.let {
            LOGGER.info("retrieved instance id from shared preferences: {}", instanceId)
            return instanceId
        } ?:run {
            LOGGER.info("no value retrieved from shared preferences, creating new instance id")
            return generateInstanceId()
        }
    }

    private fun generateInstanceId():String {
        LOGGER.info("generateInstanceId")

        val sharedPref = this.getSharedPreferences(this.packageName, Context.MODE_PRIVATE)
        val instanceId = UUID.randomUUID().toString()
        LOGGER.info("instanceId: {}", instanceId)

        with (sharedPref.edit()) {
            putString(INSTANCE_ID, instanceId)
            apply()
        }

        return instanceId
    }

    private fun loadSecretRSA():String? {
        LOGGER.info("loadSecretRSA")

        val instanceId = loadInstanceId()

        val sharedPref = this.getSharedPreferences(this.packageName, Context.MODE_PRIVATE)
        val cipheredSecret = sharedPref.getString(INSTANCE_CREDENTIAL, null)
        LOGGER.info("retrieved secret: {}", cipheredSecret)

        try {
            cipheredSecret?.let {
                val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                    load(null)
                }

                val privateKey = keyStore.getKey(instanceId, null) as? PrivateKey
                //val publicKey = keyStore.getCertificate(instanceId)?.publicKey

                privateKey?.let {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        val keyFactory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
                        val keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo::class.java)
                        LOGGER.info("key inside security hardware? {}", keyInfo.isInsideSecureHardware)
                        LOGGER.info("key require user authentication? {}", keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware)
                    }

                    val cipher = Cipher.getInstance(CIPHER_PADDING_RSA_ECB)
                    cipher.init(Cipher.DECRYPT_MODE, privateKey)
                    val decipheredSecret = String(cipher.doFinal(BaseEncoding.base64().decode(cipheredSecret)))
                    LOGGER.info("deciphered secret: {}", decipheredSecret)

                    return decipheredSecret

                } ?:run {
                    LOGGER.warn("no private key found from keystore")
                    return generateSecretRSA(instanceId)
                }

            } ?:run {
                LOGGER.info("no value retrieved from keystore, creating new secret")
                return generateSecretRSA(instanceId)
            }

        } catch (exc: Exception) {
            LOGGER.error(exc.message, exc)
            return null
        }
    }

    private fun generateSecretRSA(instanceId:String):String? {
        LOGGER.info("generateSecretRSA")

        val secret = UUID.randomUUID().toString().replace("-","")
        LOGGER.info("random secret: {}", secret)

        try {
            val keyGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                keyGenerator.initialize(
                    KeyGenParameterSpec.Builder(instanceId,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .build()
                )
            } else {
                val start = Calendar.getInstance()
                val end = Calendar.getInstance()
                end.add(Calendar.YEAR, 1)

                keyGenerator.initialize(
                    KeyPairGeneratorSpec.Builder(this.applicationContext)
                        .setAlias("rmfKey")
                        .setSubject(X500Principal("CN=rmfKey"))
                        .setSerialNumber(BigInteger.valueOf(1337))
                        .setStartDate(start.time)
                        .setEndDate(end.time)
                        .build()
                )
            }

            val keyPair = keyGenerator.generateKeyPair()
            val publicKey = keyPair.public

            val cipher = Cipher.getInstance(CIPHER_PADDING_RSA_ECB)
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            val cipheredSecret = BaseEncoding.base64().encode(cipher.doFinal(secret.toByteArray()))
            LOGGER.info("ciphered secret: {}", cipheredSecret)

            val sharedPref = this.getSharedPreferences(this.packageName, Context.MODE_PRIVATE)
            with (sharedPref.edit()) {
                putString(INSTANCE_CREDENTIAL, cipheredSecret)
                apply()
            }

            return cipheredSecret

        } catch (exc: Exception) {
            LOGGER.error(exc.message, exc)
            return null
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun loadSecretAES():String? {
        LOGGER.info("loadSecretAES")

        val instanceId = loadInstanceId()
        val sharedPref = this.getSharedPreferences(this.packageName, Context.MODE_PRIVATE)

        try {
            val cipheredSecretWithIV = sharedPref.getString(INSTANCE_CREDENTIAL, null)
            LOGGER.info("retrieved ciphered secret with initialization vector: {}", cipheredSecretWithIV)

            cipheredSecretWithIV?.let {
                val split = cipheredSecretWithIV.split(IV_SEPARATOR.toRegex())
                if (split.size != 2) throw RuntimeException("ciphered secret and IV cannot be parsed")

                val cipheredSecret = split[0]
                LOGGER.info("parsed cipher secret: {}", cipheredSecret)
                val initializationVector = split[1]
                LOGGER.info("parsed initialization vector: {}", initializationVector)

                val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                    load(null)
                }
                val keyEntry = (keyStore.getEntry(instanceId, null) as KeyStore.SecretKeyEntry?)
                keyEntry?.let {
                    val key = keyEntry.secretKey

//                    val keyFactory = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
//                    val keyInfo = keyFactory.getKeySpec(key, KeyInfo::class.java)
//                    LOGGER.info("key inside security hardware? {}", keyInfo.isInsideSecureHardware)
//                    LOGGER.info("key require user authentication? {}", keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware)

                    //val cipher = Cipher.getInstance(CIPHER_PADDING_AES_CBC)
                    //cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(BaseEncoding.base64().decode(initializationVector)))
                    val cipher = Cipher.getInstance(CIPHER_PADDING_AES_GCM)
                    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, BaseEncoding.base64().decode(initializationVector)))

                    val decipheredSecret = String(cipher.doFinal(BaseEncoding.base64().decode(cipheredSecret)))
                    LOGGER.info("deciphered secret: {}", decipheredSecret)

                    return decipheredSecret
                } ?:run {
                    LOGGER.warn("AES key not found in keystore")
                    return null
                }

            } ?:run {
                LOGGER.info("no value retrieved from keystore, creating new secret")
                return generateSecretAES(instanceId)
            }

        } catch (exc: Exception) {
            LOGGER.error(exc.message, exc)
            return null
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun generateSecretAES(instanceId: String):String? {
        LOGGER.info("generateSecretAES")

        val secret = UUID.randomUUID().toString().replace("-","")
        LOGGER.info("random secret: {}", secret)

        try {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            keyGenerator.init(
                KeyGenParameterSpec.Builder(instanceId,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    //.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    //.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build()
            )

            val key = keyGenerator.generateKey()
            //val cipher = Cipher.getInstance(CIPHER_PADDING_AES_CBC)
            val cipher = Cipher.getInstance(CIPHER_PADDING_AES_GCM)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val initializationVector = BaseEncoding.base64().encode(cipher.iv)
            LOGGER.info("initialization vector: {}", initializationVector)

            val cipheredSecret = BaseEncoding.base64().encode(cipher.doFinal(secret.toByteArray()))
            LOGGER.info("ciphered secret: {}", cipheredSecret)

            val cipheredSecretWithIV = cipheredSecret + IV_SEPARATOR + initializationVector
            LOGGER.info("ciphered secret with initialization vector: {}", cipheredSecretWithIV)

            val sharedPref = this.getSharedPreferences(this.packageName, Context.MODE_PRIVATE)
            with (sharedPref.edit()) {
                putString(INSTANCE_CREDENTIAL, cipheredSecretWithIV)
                apply()
            }

            return cipheredSecretWithIV

        } catch (exc: Exception) {
            LOGGER.error(exc.message, exc)
            return null
        }
    }

    private fun encryptStringRsa():String? {
        val plainText = "some_value"
        return encryptRSA(plainText)
    }

    private fun decryptStringRsa():String? {
        val cipheredText = encryptStringRsa()
        return cipheredText?.let {
            decryptRSA(cipheredText)
        } ?:run {
            null
        }
    }

    private fun encryptRSA(decipheredText:String):String? {
        LOGGER.info("encryptRsa")

        val secret = loadSecretRSA()
        secret?.let {
            return try {
                aeadPrimitive?.let {
                    val cipheredText = BaseEncoding.base64().encode(aeadPrimitive!!.encrypt(decipheredText.toByteArray(), secret.toByteArray()))
                    LOGGER.info("ciphered text: {}", cipheredText)
                    cipheredText
                } ?:run {
                    LOGGER.warn("no primitive found!")
                    null
                }
            } catch (exc: Exception) {
                LOGGER.error(exc.message, exc)
                null
            }
        } ?:run {
            LOGGER.warn("fail to retrieve secret")
            return null
        }
    }

    private fun decryptRSA(cipheredText:String):String? {
        LOGGER.info("decryptAES")

        val secret = loadSecretRSA()
        secret?.let {
            return try {
                aeadPrimitive?.let {
                    val decipheredText = String(aeadPrimitive!!.decrypt(BaseEncoding.base64().decode(cipheredText), secret.toByteArray()))
                    LOGGER.info("deciphered text: {}", decipheredText)
                    decipheredText
                } ?:run {
                    LOGGER.warn("no primitive found!")
                    null
                }
            } catch (exc: Exception) {
                LOGGER.error(exc.message, exc)
                null
            }
        } ?:run {
            LOGGER.warn("fail to retrieve secret")
            return null
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun encryptStringAes():String? {
        val plainText = "some_value"
        return encryptAES(plainText)
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun decryptStringAes():String? {
        val cipheredText = encryptStringAes()
        return cipheredText?.let {
            decryptAES(cipheredText)
        } ?:run {
            null
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun encryptAES(decipheredText:String):String? {
        LOGGER.info("encryptAES")

        val secret = loadSecretAES()
        secret?.let {
            return try {
                aeadPrimitive?.let {
                    val cipheredText = BaseEncoding.base64().encode(aeadPrimitive!!.encrypt(decipheredText.toByteArray(), secret.toByteArray()))
                    LOGGER.info("ciphered text: {}", cipheredText)
                    cipheredText
                } ?:run {
                    LOGGER.warn("no primitive found")
                    null
                }
            } catch (exc: Exception) {
                LOGGER.error(exc.message, exc)
                null
            }
        } ?:run {
            LOGGER.warn("fail to retrieve secret")
            return null
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun decryptAES(cipheredText:String):String? {
        LOGGER.info("decryptAES")

        val secret = loadSecretAES()
        secret?.let {
            return try {
                aeadPrimitive?.let {
                    val decipheredText = String(aeadPrimitive!!.decrypt(BaseEncoding.base64().decode(cipheredText), secret.toByteArray()))
                    LOGGER.info("deciphered text: {}", decipheredText)
                    decipheredText
                } ?:run {
                    LOGGER.warn("no primitive found!")
                    null
                }
            } catch (exc: Exception) {
                LOGGER.error(exc.message, exc)
                null
            }
        } ?:run {
            LOGGER.warn("fail to retrieve secret")
            return null
        }
    }

    private fun loadSigningKeysetECDSA():String? {
        LOGGER.info("loadSigningKeysetECDSA")

        val sharedPref = this.getSharedPreferences(this.packageName, Context.MODE_PRIVATE)
        val privateKeyJsonBase64 = sharedPref.getString(SIGNING_KEYSET, null)
        LOGGER.info("retrieved signing private key json base64 {}", privateKeyJsonBase64)

        privateKeyJsonBase64?.let {
            val privateKeyByteArray = BaseEncoding.base64().decode(privateKeyJsonBase64)
            val privateKeyJsonString = String(privateKeyByteArray)
            println("private key json: ${privateKeyJsonString}")
            val privateKeysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(privateKeyByteArray))
            val publicKeysetHandle = privateKeysetHandle.publicKeysetHandle
            val publicKeyOutputStream = ByteArrayOutputStream()
            CleartextKeysetHandle.write(publicKeysetHandle, JsonKeysetWriter.withOutputStream(publicKeyOutputStream))
            val publicKeyByteArray = publicKeyOutputStream.toByteArray()
            val publicKeyJsonString = String(publicKeyByteArray)
            println("public key json: ${publicKeyJsonString}")
            val publicKeyJsonBase64 = BaseEncoding.base64().encode(publicKeyByteArray)
            println("public key json base64: $publicKeyJsonBase64")

            return privateKeyJsonBase64
        } ?:run {
            return generateSigningKeysetECDSA()
        }

//        try {
//            privateKeyJsonBase64?.let {
//                val privateKeyByteArray = BaseEncoding.base64().decode(privateKeyJsonBase64)
//                val privateKeysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(privateKeyByteArray))
//                return privateKeysetHandle
//            } ?:run {
//                return generateSigningKeysetECDSA()
//            }
//
//        } catch (exc:Exception) {
//            LOGGER.error(exc.message, exc)
//            return null
//        }
    }

    private fun generateSigningKeysetECDSA():String? {
        LOGGER.info("generateSigningKeysetECDSA")

        return try {
            val privateKeysetHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256)
            val publicKeysetHandle = privateKeysetHandle.publicKeysetHandle

            val privateKeyOutputStream = ByteArrayOutputStream()
            CleartextKeysetHandle.write(privateKeysetHandle, JsonKeysetWriter.withOutputStream(privateKeyOutputStream))
            val privteKeyByteArray = privateKeyOutputStream.toByteArray()
            val privateKeyJsonString = String(privteKeyByteArray)
            println("private key json: ${privateKeyJsonString}")
            val privateKeyJsonBase64 = BaseEncoding.base64().encode(privteKeyByteArray)
            println("private key json base64: ${privateKeyJsonBase64} ")

            val publicKeyOutputStream = ByteArrayOutputStream()
            CleartextKeysetHandle.write(publicKeysetHandle, JsonKeysetWriter.withOutputStream(publicKeyOutputStream))
            val publicKeyByteArray = publicKeyOutputStream.toByteArray()
            val publicKeyJsonString = String(publicKeyByteArray)
            println("public key json: ${publicKeyJsonString}")
            val publicKeyJsonBase64 = BaseEncoding.base64().encode(publicKeyByteArray)
            println("public key json base64: $publicKeyJsonBase64")

            val sharedPref = this.getSharedPreferences(this.packageName, Context.MODE_PRIVATE)
            with (sharedPref.edit()) {
                putString(SIGNING_KEYSET, privateKeyJsonBase64)
                apply()
            }
            privateKeyJsonBase64

        } catch (exc:Exception) {
            LOGGER.error(exc.message, exc)
            null
        }
    }

    private fun signMessage() {
        LOGGER.info("signMessage")

        val message = "{\"pinnedDomains\":[{\"domain\":\"vncmpsit-manulife-vietnam.cs72.force.com\",\"publicKeyHashes\":{\"digestAlgorithm\":\"SHA-256\",\"hashValue\":\"5ae6406b17e601a32e4d5d929998792db6bc0dffefd646f6e44afd92d3f747e9\"},\"certificateHashes\":{\"digestAlgorithm\":\"SHA-256\",\"hashValue\":\"997d23f5c6b581c6ae865bab8fc90434e5cdce899a5c9b2597834e9ad9bebbad\"}}]}"

        val privateKeyJsonBase64 = loadSigningKeysetECDSA()
        privateKeyJsonBase64?.let {
            try {
                val privateKeyByteArray = BaseEncoding.base64().decode(privateKeyJsonBase64)
                val privateKeysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(privateKeyByteArray))
                val publicKeysetHandle = privateKeysetHandle.publicKeysetHandle

                val signer = PublicKeySignFactory.getPrimitive(privateKeysetHandle)
                val signature = signer.sign(message.toByteArray())
                val signatureBase64String = BaseEncoding.base64().encode(signature)
                val signatureHexString = BaseEncoding.base16().encode(signature)
                println("signature base64: $signatureBase64String")
                println("signature HEX: $signatureHexString")

                val verifier = PublicKeyVerifyFactory.getPrimitive(publicKeysetHandle)
                try {
                    verifier.verify(signature, message.toByteArray())
                } catch (exc: GeneralSecurityException) {
                    LOGGER.warn("fail to verify signature: {}", exc.message)
                }
                LOGGER.info("signature verification success")

            } catch (exc:Exception) {
                LOGGER.error(exc.message, exc)
            }

        } ?:run {
            LOGGER.warn("keyset cannot be retrieved, fail to sign message")
        }
    }
}
