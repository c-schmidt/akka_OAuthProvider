package org.scoding.oauth

import akka.actor.Actor
import Actor._
import net.oauth.OAuthProblemException
import net.oauth.OAuthAccessor
import net.oauth.OAuthConsumer
import net.oauth.OAuthException
import net.oauth.OAuthMessage
import net.oauth.OAuthProblemException
import net.oauth.OAuthValidator
import net.oauth.OAuth
import net.oauth.SimpleOAuthValidator
import net.oauth.server.OAuthServlet
import scala.collection.JavaConversions._ 
import net.oauth.server.HttpRequestMessage
import play.api.mvc.{Request, AnyContent, SimpleResult}
import play.api.mvc.Results.{Ok, Status}

class OAuthProvider extends Actor {  
  OAuthUtil.loadConsumers

  def receive = {
    case GetRequesetToken(request) => 
      val parameters = getHeader(request)
      val requestMessage = new OAuthMessage(request.method,"http://" + request.host + request.path, getParameters(request))
      println("### REQUEST REQUEST TOKEN: " + parameters)
      try{
      parameters.get("oauth_consumer_key") match {
        case Some(key) => 
          val consumer: OAuthConsumer = OAuthUtil.getConsumer(key)
          val accessor: OAuthAccessor = new OAuthAccessor(consumer)
          OAuthUtil.validator.validateMessage(requestMessage, accessor); 
          {
            // Support the 'Variable Accessor Secret' extension
            // described in http://oauth.pbwiki.com/AccessorSecret
            val secret = parameters.get("oauth_accessor_secret")
            if(!secret.isEmpty) {
              accessor.setProperty(OAuthConsumer.ACCESSOR_SECRET, secret)
            }
          }
          OAuthUtil.generateRequestToken(accessor)
          val result = 
          OAuth.formEncode(OAuth.newList("oauth_token", accessor.requestToken, "oauth_token_secret", accessor.tokenSecret))
          println("### RESPONSE REQUEST TOKEN: " + result)
          sender ! OAuthResult(Ok(result))  
      
        case None =>
          throw new OAuthProblemException(OAuth.Problems.PARAMETER_ABSENT)
      }
      }catch {
        //TODO: exception handling, statuscodes etc.
        case e: OAuthProblemException => 
          sender ! OAuthResult(
              Status(e.getHttpStatusCode())(e.getMessage()))
        case _ =>  
      }
    case GetAccessToken(request) =>    
      try{
      val parameters = getHeader(request)
      println("### REQUEST ACCESS TOKEN: " + parameters)
      val requestMessage = new OAuthMessage(request.method,"http://" + request.host + request.path, getParameters(request))  
      
      val accessor = OAuthUtil.getAccessor(requestMessage)
          
      OAuthUtil.validator.validateMessage(requestMessage, accessor)
      
      parameters.get("oauth_consumer_key") match {
        case Some(key) => OAuthUtil.markAsAuthorized(accessor, key)
        case _ =>  
      }
          
      // make sure token is authorized
      if(!java.lang.Boolean.TRUE == accessor.getProperty("authorized")) {
        val problem = new OAuthProblemException("permission_denied")
        throw problem
      }
     
      OAuthUtil.generateAccessToken(accessor)
         
      val result = 
        OAuth.formEncode(OAuth.newList("oauth_token", accessor.accessToken, "oauth_token_secret", accessor.tokenSecret))
      println("### RESPONSE ACCESS TOKEN: " + result)
      sender ! OAuthResult(Ok(result))
      }catch {
        //TODO: exception handling, statuscodes etc.
        case e: OAuthProblemException => 
          sender ! OAuthResult(
              Status(e.getHttpStatusCode())(e.getMessage()))
      }
    case ValidateSignature(request) =>
      try{
      val parameters = getHeader(request)
      println("### VALIDATE REQUEST: " + parameters)
      val requestMessage = new OAuthMessage(request.method,"http://" + request.host + request.path, getParameters(request))  
      
      val accessor = OAuthUtil.getAccessor(requestMessage)
          
      OAuthUtil.validator.validateMessage(requestMessage, accessor)
      
      sender ! OAuthValidationResult(true, Ok(""))
      
      }catch {
        //TODO: exception handling, statuscodes etc.
        case e: OAuthProblemException => 
          sender ! OAuthValidationResult(
              false,
              Status(e.getHttpStatusCode())(e.getMessage()))
      }  
    case _ => 
  }
 
  def getHeader(request: Request[AnyContent]): Map[String,String] = {
    import java.net.URLDecoder._
    request.headers.toSimpleMap.get("AUTHORIZATION") match {
      case Some(header) => OAuthParser.parseHeader(header).map(e => e._1 -> decode(e._2,"UTF-8")) 
      case _ => Map[String,String]()  
    }
  }
  
  def getParameters(request: Request[AnyContent]): java.util.List[OAuth.Parameter] = {
    val list = new java.util.ArrayList[OAuth.Parameter]()
    val parameters = getHeader(request)
    parameters.map(e => list.add(new OAuth.Parameter(e._1,e._2)))
    list     
  }
}