package net.kaleidos.grails.plugin.security.stateless.token

import org.grails.testing.GrailsUnitTest
import spock.lang.Specification
import net.kaleidos.grails.plugin.security.stateless.*
import net.kaleidos.grails.plugin.security.stateless.token.*

class JwtStatelessTokenProviderSpec extends Specification implements GrailsUnitTest {

   def tokenProvider

   def setup() {
      tokenProvider = new JwtStatelessTokenProvider()
      tokenProvider.cryptoService = new CryptoService()
      tokenProvider.cryptoService.init 'secret'
   }

   def cleanup() {
   }

   void "test something"() {
      expect:"fix me"
      true == true
   }
}
