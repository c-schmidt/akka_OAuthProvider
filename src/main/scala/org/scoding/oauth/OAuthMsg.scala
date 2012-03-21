package org.scoding.oauth

import play.api.mvc.{Request, AnyContent, SimpleResult}

sealed trait OAuthMsg 
case class GetRequesetToken(request: Request[AnyContent]) extends OAuthMsg
case class GetAccessToken(request: Request[AnyContent]) extends OAuthMsg
case class ValidateSignature(request: Request[AnyContent]) extends OAuthMsg
case class OAuthResult(response: SimpleResult[String]) extends OAuthMsg
case class OAuthValidationResult(hasAccess: Boolean, statusMsg: SimpleResult[String])