package com.example.jeffrey.securestorageandroid

import android.content.Context
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.support.v7.app.AppCompatActivity
import android.widget.Button
import com.google.common.io.BaseEncoding
import org.slf4j.LoggerFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec

class MainActivity : AppCompatActivity() {

    var iv:ByteArray? = null

    companion object {
        private val LOGGER = LoggerFactory.getLogger(MainActivity::class.java)

        const val ANDROID_KEYSTORE:String = "AndroidKeyStore"

        const val INSTANCE_ID:String = "guid"
        const val INSTANCE_CREDENTIAL:String = "credential"

        const val CIPHER_PADDING_RSA_ECB:String = "RSA/ECB/PKCS1Padding"
        const val CIPHER_PADDING_AES_CBC:String = "AES/CBC/PKCS7Padding"

        const val IV_SEPARATOR = ":" // not used in base64 encoding table
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initUI()
    }

    private fun initUI() {
        val generateInstanceIdBtn = findViewById<Button>(R.id.generateInstanceIdBtn)
        generateInstanceIdBtn.setOnClickListener {
            this.generateInstanceId()
        }

        val loadInstanceIdBtn = findViewById<Button>(R.id.loadInstanceIdBtn)
        loadInstanceIdBtn.setOnClickListener {
            this.loadInstanceId()
        }

        val generateSecretRsaBtn = findViewById<Button>(R.id.generateSecretRsaBtn)
        generateSecretRsaBtn.setOnClickListener {
            this.generateSecretRSA(this.loadInstanceId())
        }

        val loadSecretRsaBtn = findViewById<Button>(R.id.loadSecretRsaBtn)
        loadSecretRsaBtn.setOnClickListener {
            this.loadSecretRSA()
        }

        val generateSecretAesBtn = findViewById<Button>(R.id.generateSecretAesBtn)
        generateSecretAesBtn.setOnClickListener {
            this.generateSecretAES(this.loadInstanceId())
        }

        val loadSecretAesBtn = findViewById<Button>(R.id.loadSecretAesBtn)
        loadSecretAesBtn.setOnClickListener {
            this.loadSecretAES()
        }
    }

    private fun loadInstanceId():String {
        LOGGER.info("loadInstanceId")

        val sharedPref = this.getSharedPreferences(this.packageName, Context.MODE_PRIVATE)
        val instanceId:String? = sharedPref.getString(INSTANCE_ID, null)

        instanceId?.let {
            LOGGER.info("retrieved instance id from shared preferences: {}", instanceId)
            return instanceId
        }.run {
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
            commit()
        }

        return instanceId
    }

    private fun loadSecretRSA():String {
        LOGGER.info("loadSecretRSA")

        val instanceId = loadInstanceId()

        val sharedPref = this.getSharedPreferences(this.packageName, Context.MODE_PRIVATE)
        val cipheredSecret = sharedPref.getString(INSTANCE_CREDENTIAL, null)
        LOGGER.info("retrieved secret: {}", cipheredSecret)

        cipheredSecret?.let {
            val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                load(null)
            }

            val privateKey = keyStore.getKey(instanceId, null) as PrivateKey?
            //val publicKey = keyStore.getCertificate(instanceId)?.publicKey

            val cipher = Cipher.getInstance(CIPHER_PADDING_RSA_ECB)
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            val decipheredSecret = String(cipher.doFinal(BaseEncoding.base64().decode(cipheredSecret)))
            LOGGER.info("deciphered secret: {}", decipheredSecret)

            return decipheredSecret

        }.run {
            LOGGER.info("no value retrieved from keystore, creating new secret")
            return generateSecretRSA(instanceId)
        }
    }

    private fun generateSecretRSA(instanceId:String):String {
        LOGGER.info("generateSecretRSA")

        val secret = UUID.randomUUID().toString().replace("-","")
        LOGGER.info("random secret: {}", secret)

        val keyGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
        keyGenerator.initialize(
            KeyGenParameterSpec.Builder(instanceId,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .build()
        )

        val keyPair = keyGenerator.generateKeyPair()
        val publicKey = keyPair.public

        val cipher = Cipher.getInstance(CIPHER_PADDING_RSA_ECB)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val cipheredSecret = BaseEncoding.base64().encode(cipher.doFinal(secret.toByteArray()))
        LOGGER.info("ciphered secret: {}", cipheredSecret)

        val sharedPref = this.getSharedPreferences(this.packageName, Context.MODE_PRIVATE)
        with (sharedPref.edit()) {
            putString(INSTANCE_CREDENTIAL, cipheredSecret)
            commit()
        }

        return cipheredSecret
    }

    private fun loadSecretAES():String {
        LOGGER.info("loadSecretAES")

        val instanceId = loadInstanceId()
        val sharedPref = this.getSharedPreferences(this.packageName, Context.MODE_PRIVATE)

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
            val key = (keyStore.getEntry(instanceId, null) as KeyStore.SecretKeyEntry)?.secretKey

            val cipher = Cipher.getInstance(CIPHER_PADDING_AES_CBC)
            cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(BaseEncoding.base64().decode(initializationVector)))

            val decipheredSecret = String(cipher.doFinal(BaseEncoding.base64().decode(cipheredSecret)))
            LOGGER.info("deciphered secret: {}", decipheredSecret)

            return decipheredSecret

        }.run {
            LOGGER.info("no value retrieved from keystore, creating new secret")
            return generateSecretAES(instanceId)
        }
    }

    private fun generateSecretAES(instanceId: String):String {
        LOGGER.info("generateSecretAES")

        val secret = UUID.randomUUID().toString().replace("-","")
        LOGGER.info("random secret: {}", secret)

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        keyGenerator.init(
            KeyGenParameterSpec.Builder(instanceId,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build()
        )

        val key = keyGenerator.generateKey()
        val cipher = Cipher.getInstance(CIPHER_PADDING_AES_CBC)
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
            commit()
        }

        return cipheredSecretWithIV
    }
}
