package com.example.jeffrey.securestorageandroid

import android.support.test.InstrumentationRegistry
import android.support.test.runner.AndroidJUnit4
import com.google.common.io.BaseEncoding
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.JsonKeysetReader
import com.google.crypto.tink.JsonKeysetWriter
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.signature.PublicKeySignFactory
import com.google.crypto.tink.signature.PublicKeyVerifyFactory
import com.google.crypto.tink.signature.SignatureKeyTemplates
import org.json.JSONException
import org.json.JSONObject
import org.junit.*
import org.junit.Assert.assertEquals
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.security.GeneralSecurityException

/**
 * Instrumented test, which will execute on an Android device.
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {

    companion object {
        init { }

        @BeforeClass @JvmStatic fun setup() {
            TinkConfig.register()
        }

        @AfterClass @JvmStatic fun teardown() { }
    }

    @Before
    fun prepareTest() { }

    @After
    fun cleanupTest() { }

    @Test
    fun useAppContext() {
        // Context of the app under test.
        val appContext = InstrumentationRegistry.getTargetContext()
        assertEquals("com.example.jeffrey.securestorageandroid", appContext.packageName)
    }

    @Test
    fun generateEcdsaSigningKeysetToJsonString() {
        // parsing ketset from json require android util which cannot be mocked in unit-test

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

        try {
            JSONObject(privateKeyJsonString)
            JSONObject(publicKeyJsonString)
            restoreEcdsaSigningKeysetFromJsonString(privateKeyJsonString, publicKeyJsonString)

        } catch (exc:JSONException) {
            Assert.fail(exc.message)
        }
    }

    private fun restoreEcdsaSigningKeysetFromJsonString(privateKeyJsonString:String, publicKeyJsonString:String) {
        // parsing ketset from json require android util which cannot be mocked in unit-test

        val privateKeysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(privateKeyJsonString.toByteArray()))
        val publicKeysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(publicKeyJsonString.toByteArray()))

        //=== verify integrity of key after restored from base64 ===
        Assert.assertEquals(
            publicKeysetHandle.keysetInfo.keyInfoCount,
            privateKeysetHandle.publicKeysetHandle.keysetInfo.keyInfoCount)

        val publicKeyMap = publicKeysetHandle.keysetInfo.keyInfoList.map{ keyInfo -> keyInfo.keyId to keyInfo }.toMap()
        val tempPublicKeyMap = privateKeysetHandle.publicKeysetHandle.keysetInfo.keyInfoList.map{ keyInfo -> keyInfo.keyId to keyInfo }.toMap()

        publicKeyMap.forEach { keyId, keyInfo ->
            val tempKeyInfo= tempPublicKeyMap[keyId]
            Assert.assertNotNull(tempKeyInfo)
            tempKeyInfo?.let {
                Assert.assertEquals(keyId, tempKeyInfo.keyId)
                Assert.assertEquals(keyInfo.typeUrl, tempKeyInfo.typeUrl)
                Assert.assertEquals(keyInfo.status, tempKeyInfo.status)
                Assert.assertEquals(keyInfo.outputPrefixType, tempKeyInfo.outputPrefixType)
                Assert.assertEquals(keyInfo.hashCode(), tempKeyInfo.hashCode())
            } ?:run {
                Assert.fail()
            }
        }
        //=== verify finish ===

        verifySignedMessage(privateKeysetHandle, publicKeysetHandle)
    }

    private fun verifySignedMessage(privateKeysetHandle:KeysetHandle, publicKeysetHandle:KeysetHandle) {
        val message = "abcdef"

        val signer = PublicKeySignFactory.getPrimitive(privateKeysetHandle)
        val signature = signer.sign(message.toByteArray())
        val signatureBase64String = BaseEncoding.base64().encode(signature)
        val signatureHexString = BaseEncoding.base16().encode(signature)
        println("signature base64: $signatureBase64String")
        println("signature HEX: $signatureHexString")

        val verifier = PublicKeyVerifyFactory.getPrimitive(publicKeysetHandle)
        try {
            verifier.verify(signature, message.toByteArray())
        } catch (exc:GeneralSecurityException) {
            Assert.fail(exc.message)
        }
    }
}
