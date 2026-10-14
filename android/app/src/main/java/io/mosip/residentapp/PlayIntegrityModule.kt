package io.mosip.residentapp

import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager

class PlayIntegrityModule(private val ctx: ReactApplicationContext) :
  ReactContextBaseJavaModule(ctx) {

  private var provider: StandardIntegrityManager.StandardIntegrityTokenProvider? = null

  override fun getName() = "PlayIntegrity"

  @ReactMethod
  fun prepareProvider(cloudProjectNumber: String, promise: Promise) {
    try {
      val manager = IntegrityManagerFactory.createStandard(ctx)
      manager.prepareIntegrityToken(
        StandardIntegrityManager.PrepareIntegrityTokenRequest.builder()
          .setCloudProjectNumber(cloudProjectNumber.toLong())
          .build()
      ).addOnSuccessListener { p ->
        provider = p
        promise.resolve(null)
      }.addOnFailureListener { e ->
        promise.reject("ERR_INTEGRITY_PREPARE", e.message, e)
      }
    } catch (e: Exception) {
      promise.reject("ERR_INTEGRITY_PREPARE", e.message, e)
    }
  }

  @ReactMethod
  fun requestToken(requestHash: String, promise: Promise) {
    val p = provider
    if (p == null) {
      promise.reject("ERR_INTEGRITY_PROVIDER_INVALID", "Provider not prepared")
      return
    }
    p.request(
      StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
        .setRequestHash(requestHash)
        .build()
    ).addOnSuccessListener { r ->
      promise.resolve(r.token())
    }.addOnFailureListener { e ->
      promise.reject("ERR_INTEGRITY_REQUEST", e.message, e)
    }
  }
}
