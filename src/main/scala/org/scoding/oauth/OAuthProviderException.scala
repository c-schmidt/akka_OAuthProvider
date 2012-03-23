package org.scoding.oauth



object OAuthProviderException {
  import play.api.mvc.Results.Status 
  import play.api.mvc.{Request, AnyContent, SimpleResult}
  import play.api.libs.json._
  import Json._
  
  private val errorTypes = Map[String,Int](
        "token_not_authorized" -> 401, 
        "invalid_used_nonce" -> 401,
        "signature_invalid" -> 401,
        "invalid_expired_token" -> 401,
        "token_expired" -> 401,
        "invalid_consumer_key" -> 401,
        "consumer_key_refused" -> 401,
        "timestamp_refused" -> 400,
        "parameter_rejected" -> 400,
        "parameter_absent" -> 400,
        "version_rejected" -> 400,
        "signature_method_rejected" -> 400,
        "oauth_parameters_absent" -> 400,
        "oauth_parameters_rejected" -> 400,
        "permission_denied" -> 550
      )
  
  private def getStatus(message: String) = errorTypes.get(message)
 
  private def mkError(message: String, status: Int) = {
    Status(status)(message) 
  }
  
  def handle(message: String): SimpleResult[String] = {
    getStatus(message) match {
      case Some(status) => mkError(message, status)
      case None => mkError("internal_server_error", 500)   
    }
  }
}  
