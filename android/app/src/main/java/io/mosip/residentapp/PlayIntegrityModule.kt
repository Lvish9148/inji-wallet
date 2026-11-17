package io.mosip.residentapp

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.facebook.react.bridge.*
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.MessageDigest

class PlayIntegrityModule(
  private val ctx: ReactApplicationContext
) : ReactContextBaseJavaModule(ctx) {

  companion object {
    private const val KEY_ALIAS = "mimoto_integrity_key_v2"
  }

  override fun getName() = "KeyAttestation"

  @ReactMethod
  fun hasKey(promise: Promise) {
    try {
      val store = KeyStore.getInstance("AndroidKeyStore")
      store.load(null)
      promise.resolve(store.containsAlias(KEY_ALIAS))
    } catch (e: Exception) {
      promise.reject("ERR_KEY_CHECK", e.message, e)
    }
  }
  @ReactMethod
  fun deleteKey(promise: Promise) {
    try {
      val store = KeyStore.getInstance("AndroidKeyStore")
      store.load(null)
      if (store.containsAlias(KEY_ALIAS)) {
        store.deleteEntry(KEY_ALIAS)
      }
      promise.resolve(true)
    } catch (e: Exception) {
      promise.reject("ERR_KEY_DELETE", e.message, e)
    }
  }

  @ReactMethod
  fun generateAttestedKey(challenge: String, promise: Promise) {
    try {
      require(challenge.isNotBlank()) { "Challenge cannot be empty" }
      require(challenge.toByteArray(Charsets.UTF_8).size <= 128) {
        "Challenge exceeds 128 bytes"
      }

      val store = KeyStore.getInstance("AndroidKeyStore")
      store.load(null)

      // Replace the existing key when creating a new attestation.
      if (store.containsAlias(KEY_ALIAS)) {
        promise.reject("ERR_KEY_EXISTS", "Attested key already exists")
        return
      }

      val generator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_EC,
        "AndroidKeyStore"
      )

      val spec = KeyGenParameterSpec.Builder(
        KEY_ALIAS,
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
      )
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setAttestationChallenge(challenge.toByteArray(Charsets.UTF_8))
        .setUserAuthenticationRequired(false)
        .build()

      generator.initialize(spec)
      generator.generateKeyPair()

      val chain = store.getCertificateChain(KEY_ALIAS)
        ?: error("Attestation certificate chain unavailable")

      val result = Arguments.createArray()
      chain.forEach { certificate ->
        result.pushString(
          Base64.encodeToString(certificate.encoded, Base64.NO_WRAP)
        )
      }

      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("ERR_KEY_ATTESTATION", e.message, e)
    }
  }

  @ReactMethod
  fun getAttestationChain(promise: Promise) {
    try {
      val store = KeyStore.getInstance("AndroidKeyStore")
      store.load(null)

      val chain = store.getCertificateChain(KEY_ALIAS)
        ?: error("No attested key found")

      val result = Arguments.createArray()
      chain.forEach { certificate ->
        result.pushString(
          Base64.encodeToString(certificate.encoded, Base64.NO_WRAP)
        )
      }

      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("ERR_ATTESTATION_CHAIN", e.message, e)
    }
  }

  @ReactMethod
  fun getKeyId(promise: Promise) {
    try {
      val store = KeyStore.getInstance("AndroidKeyStore")
      store.load(null)

      val cert = store.getCertificate(KEY_ALIAS)
        ?: error("No attested key found")

      val digest = MessageDigest.getInstance("SHA-256")
        .digest(cert.publicKey.encoded)

      promise.resolve(
        digest.joinToString("") {
          "%02x".format(it.toInt() and 0xff)
        }
      )
    } catch (e: Exception) {
      promise.reject("ERR_KEY_ID", e.message, e)
    }
  }

  @ReactMethod
  fun signPayload(payload: String, promise: Promise) {
    try {
      val store = KeyStore.getInstance("AndroidKeyStore")
      store.load(null)

      val key = store.getKey(KEY_ALIAS, null) as? PrivateKey
        ?: error("No attested signing key found")

      val signer = Signature.getInstance("SHA256withECDSA")
      signer.initSign(key)
      signer.update(payload.toByteArray(Charsets.UTF_8))

      promise.resolve(
        Base64.encodeToString(signer.sign(), Base64.NO_WRAP)
      )
    } catch (e: Exception) {
      promise.reject("ERR_REQUEST_SIGNATURE", e.message, e)
    }
  }
}
