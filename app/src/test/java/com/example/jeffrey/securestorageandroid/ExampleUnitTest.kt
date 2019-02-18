package com.example.jeffrey.securestorageandroid

import com.google.common.io.BaseEncoding
import com.google.crypto.tink.BinaryKeysetReader
import com.google.crypto.tink.BinaryKeysetWriter
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.signature.PublicKeySignFactory
import com.google.crypto.tink.signature.PublicKeyVerifyFactory
import com.google.crypto.tink.signature.SignatureKeyTemplates
import org.junit.*
import org.junit.Assert.assertEquals
import java.io.ByteArrayOutputStream
import java.security.GeneralSecurityException


/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
class ExampleUnitTest {

    companion object {
        init { }

        @BeforeClass
        @JvmStatic fun setup() {
            TinkConfig.register()
        }

        @AfterClass
        @JvmStatic fun teardown() { }
    }

    @Before
    fun prepareTest() { }

    @After
    fun cleanupTest() { }

    @Test
    fun addition_isCorrect() {
        assertEquals(4, 2 + 2)
    }

    @Test
    fun generateEcdsaSigningKeysetToBase64() {
        val privateKeysetHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256)
        val publicKeysetHandle = privateKeysetHandle.publicKeysetHandle

        val privateKeyOutputStream = ByteArrayOutputStream()
        CleartextKeysetHandle.write(privateKeysetHandle, BinaryKeysetWriter.withOutputStream(privateKeyOutputStream))
        val privteKeyByteArray = privateKeyOutputStream.toByteArray()
        val privateKeyBase64 = BaseEncoding.base64().encode(privteKeyByteArray)
        println("private key base64: $privateKeyBase64")

        val publicKeyOutputStream = ByteArrayOutputStream()
        CleartextKeysetHandle.write(publicKeysetHandle, BinaryKeysetWriter.withOutputStream(publicKeyOutputStream))
        val publicKeyByteArray = publicKeyOutputStream.toByteArray()
        val publicKeyBase64 = BaseEncoding.base64().encode(publicKeyByteArray)
        println("public key base64: $publicKeyBase64")

        restoreEcdsaSigningKeysetFromBase64(privateKeyBase64, publicKeyBase64)
    }

    private fun restoreEcdsaSigningKeysetFromBase64(privateKeyBase64:String, publicKeyBase64:String) {
        val privateKeyByteArray = BaseEncoding.base64().decode(privateKeyBase64)
        val privateKeysetHandle = CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(privateKeyByteArray))

        val publicKeyByteArray = BaseEncoding.base64().decode(publicKeyBase64)
        val publicKeysetHandle = CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(publicKeyByteArray))

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
        } catch (exc: GeneralSecurityException) {
            Assert.fail(exc.message)
        }
    }
}
