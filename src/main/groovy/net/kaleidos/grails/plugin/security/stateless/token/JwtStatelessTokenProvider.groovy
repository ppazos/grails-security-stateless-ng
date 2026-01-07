package net.kaleidos.grails.plugin.security.stateless.token

import groovy.json.JsonBuilder
import groovy.json.JsonSlurper
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j

import org.slf4j.Logger
import org.slf4j.LoggerFactory

import org.joda.time.DateTime
import org.joda.time.format.DateTimeFormatter
import org.joda.time.format.ISODateTimeFormat

import java.text.SimpleDateFormat

import net.kaleidos.grails.plugin.security.stateless.CryptoService
import net.kaleidos.grails.plugin.security.stateless.utils.UrlSafeBase64Utils
import net.kaleidos.grails.plugin.security.stateless.exception.StatelessValidationException

@Slf4j
class JwtStatelessTokenProvider implements StatelessTokenProvider {

   private static final String BEARER = "Bearer "

   CryptoService cryptoService
   Integer expirationTime

   public void init(Integer expirationTime) {
      this.expirationTime = expirationTime
   }

   private String generateTokenCommon(String userName, String salt = null, Map<String, String> extraData = [:], Integer anExpirationTime)
   {
      def data = [username:userName]

      if (extraData) {
         data["extradata"] = extraData
      }

      if (salt != null) {
         data["salt"] = salt
      }

      DateTimeFormatter formatter = ISODateTimeFormat.dateTime()
      data["issued_at"] = formatter.print(new DateTime())

      if (anExpirationTime != null) {
         data["expires_at"] = formatter.print(new DateTime().plusMinutes(anExpirationTime))
      }

      String header = new JsonBuilder([alg:"HS256", typ: "JWT"])
      String payload = new JsonBuilder(data).toString()

      // Debug - log these to see what's being signed
      println "Header: ${header}"
      println "Payload: ${payload}"
      
      String toSign = "${UrlSafeBase64Utils.encode(header.bytes)}.${UrlSafeBase64Utils.encode(payload.bytes)}"
      println "To sign: ${toSign}"
      
      String signature = cryptoService.hash(toSign)
      
      return "${toSign}.${signature}"
   }

   String generateToken(String userName, String salt=null, Map<String,String> extraData=[:])
   {
      return generateTokenCommon(userName, salt, extraData, this.expirationTime)
   }

   String generateTokenCustomExpiration(String userName, String salt=null, Map<String,String> extraData, Integer customExpirationTime)
   {
      return generateTokenCommon(userName, salt, extraData, customExpirationTime)
   }

   Map validateAndExtractToken(String token)
   {
      if (!token) {
         log.debug "Token must be present"
         throw new StatelessValidationException("Invalid token")
      }

      if (token.startsWith(BEARER)){
         token = token.substring(BEARER.size())
      }

      def (header64, payload64, signature) = token.tokenize(".")

      if (header64 == null || payload64 == null || signature == null) {
         log.debug "Token should have two points to split"
         throw new StatelessValidationException("Invalid token")
      }

      // Validate signature
      String expectedSignature = cryptoService.hash("${header64}.${payload64}")

      if (signature != expectedSignature) {
         throw new StatelessValidationException("Invalid token")
      }

      // Extract the payload
      def slurper = new JsonSlurper()
      def payload = new String(UrlSafeBase64Utils.decode(payload64))
      def parsed = (Map)slurper.parseText(payload)

      //println "PARSED TOKEN : "+ slurper.parseText(payload)
      // Check expiration
      def now = new Date()

      def s = parsed.expires_at
      if (s)
      {
         def f = "yyyy-MM-dd'T'HH:mm:ss.SSSX"
         SimpleDateFormat sdf = new SimpleDateFormat(f)
         sdf.setLenient(false)
         def expires_at = sdf.parse(s)

         if (expires_at < now)
         {
            throw new StatelessValidationException("Expired token")
         }
      }

      return parsed
    }
}
