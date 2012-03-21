package org.scoding.oauth

import net.oauth.OAuthAccessor
import net.oauth.OAuthConsumer
import net.oauth.OAuthException
import net.oauth.OAuthMessage
import net.oauth.OAuthProblemException
import net.oauth.OAuthValidator
import net.oauth.SimpleOAuthValidator
import scala.collection.JavaConversions._
import java.io.InputStream
import java.net.URL
import java.util.Collection
import java.util.Collections
import java.util.HashMap
import java.util.HashSet
import java.util.Map
import java.util.Properties;
import java.io.FileInputStream
import org.apache.commons.codec.digest.DigestUtils

/* This object is more or less a quick and dirty translation of the SampleOAuthProvider form
 * http://code.google.com/p/oauth/source/browse/code/java/example/oauth-provider/src/net/oauth/example/provider/core/SampleOAuthProvider.java?r=467
 */


object OAuthUtil {
  val validator = new SimpleOAuthValidator()

  //TODO: Use scala's Map + akka's stm support
  private val allConsumers:Map[String, OAuthConsumer] 
    = Collections.synchronizedMap(new HashMap[String,OAuthConsumer](10))
    
  //TODO: Use scala's Set + akka's stm support
  private val allTokens = new HashSet[OAuthAccessor]()

  var consumerProperties: Option[Properties] = None
    
  def loadConsumers = synchronized {
    var p = consumerProperties  
    if (p.isEmpty) {
      val userDir = System.getProperty("user.dir")
      val userHome = System.getProperty("user.home")
      val configFile = userDir + "/provider.properties"
      var probs = new Properties
      probs load new FileInputStream(configFile)
      p=Some(probs)
    }
    consumerProperties = p
        
    // for each entry in the properties file create a OAuthConsumer
    for(prop <- p.head.entrySet()) {
      val consumer_key = prop.getKey().toString()
      // make sure it's key not additional properties
      if(!consumer_key.contains(".")){
        val consumer_secret = prop.getValue().toString()
        if(consumer_secret != null){
          val consumer_description = p.head.getProperty(consumer_key + ".description").toString()
          val consumer_callback_url =  p.head.getProperty(consumer_key + ".callbackURL").toString()
          // Create OAuthConsumer w/ key and secret
          val consumer = new OAuthConsumer(
            consumer_callback_url, 
            consumer_key, 
            consumer_secret, 
            null)
          consumer.setProperty("name", consumer_key)
          consumer.setProperty("description", consumer_description)
          allConsumers.put(consumer_key, consumer)
        }
      }
    }
  }
  
  def getConsumer(key: String): OAuthConsumer = synchronized {
    val consumer:OAuthConsumer = OAuthUtil.allConsumers.get(key)
    if(consumer == null) {
      throw  new OAuthProblemException("token_rejected") 
    }
    consumer
  }
  
  def getAccessor(requestMessage: OAuthMessage): OAuthAccessor = synchronized {   
    val consumer_token = requestMessage.getToken()
    var accessor: Option[OAuthAccessor] = None
        
    val accessorList = OAuthUtil.allTokens.filter(a => 
      a.accessToken == consumer_token || a.requestToken == consumer_token)  
      for(a <- accessorList){
      if(a.requestToken != null) {
        if(a.requestToken.equals(consumer_token)) accessor = Some(a)
      }
      else if(a.accessToken.equals(consumer_token)) accessor = Some(a)
    }
                 
    accessor match {
      case Some(a) => a 
      case None => throw new OAuthProblemException("token_expired") 
    }         
  }
  
  def markAsAuthorized(accessor: OAuthAccessor, userId: String) {
    // first remove the accessor from cache
    allTokens.remove(accessor)
       
    accessor.setProperty("user", userId)   
    accessor.setProperty("authorized", true)
        
    // update token in local cache
    allTokens.add(accessor)
  }
  
  def generateRequestToken(accessor: OAuthAccessor) = synchronized{

    // generate oauth_token and oauth_secret
    val consumer_key = accessor.consumer.getProperty("name")
    // generate token and secret based on consumer_key
        
    // for now use md5 of name + current time as token
    val token_data = consumer_key + System.nanoTime().toString
    val token = DigestUtils.md5Hex(token_data)
    // for now use md5 of name + current time + token as secret
    val secret_data = consumer_key + System.nanoTime().toString() + token
    val secret = DigestUtils.md5Hex(secret_data)
    accessor.requestToken = token
    accessor.tokenSecret = secret
    accessor.accessToken = null
    
    // add to the local cache
    allTokens.add(accessor)     
  }

  def generateAccessToken(accessor: OAuthAccessor) = synchronized {
    // generate oauth_token and oauth_secret
    val consumer_key = accessor.consumer.getProperty("name")
    // generate token and secret based on consumer_key
        
    // for now use md5 of name + current time as token
    val token_data = consumer_key + System.nanoTime().toString()
    val token = DigestUtils.md5Hex(token_data)
    // first remove the accessor from cache
    allTokens.remove(accessor)
        
    accessor.requestToken = null
    accessor.accessToken = token
        
    // update token in local cache
    allTokens.add(accessor)
  }   
}

import scala.util.parsing.combinator._
import scala.util.matching.Regex
	 
/* This object is used to get all parameters form the 
 * request header
 */
object OAuthParser extends RegexParsers {
  private def prefix = regex(new Regex("[a-z]*[_]+[a-z]*[_]?[a-z]*[^=]")) 
  private def suffix = regex(new Regex("[ ]*[^\"]+"))
  
  private def parsePrefix(str: String): String = {
    parse(prefix, str) match {
      case OAuthParser.Success(result,_) => result.toString()
      case _ => ""
    }
  }
  
  private def parseSuffix(str: String): String = {
    parse(suffix, str.reverse.drop(1)) match {
      case OAuthParser.Success(result,_) => result.toString().reverse
      case _ => ""
    }
  }
  
  def parseHeader(str: String): scala.collection.immutable.Map[String,String] = {
    val header = str.split(" ").flatMap(_.split(","))
    var result = scala.collection.immutable.Map[String,String]() 
    if(header.contains("OAuth")) {
      for(parameter <- header.tail) {
        result += parsePrefix(parameter) -> parseSuffix(parameter)  
      }
      result
    } else result
  }
}