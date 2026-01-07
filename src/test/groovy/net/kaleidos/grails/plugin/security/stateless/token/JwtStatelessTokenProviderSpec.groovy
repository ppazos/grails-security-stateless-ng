package net.kaleidos.grails.plugin.security.stateless.token

import grails.testing.services.ServiceUnitTest
import spock.lang.Specification
import net.kaleidos.grails.plugin.security.stateless.*

class JwtStatelessTokenProviderSpec extends Specification {
    
    JwtStatelessTokenProvider tokenProvider
    
    def setup() {
        tokenProvider = new JwtStatelessTokenProvider()
        tokenProvider.cryptoService = new CryptoService()
        tokenProvider.cryptoService.init('secret')
        tokenProvider.init(60)
    }
    
    def cleanup() {
    }
    
    void "test token with default expiration"() {
        when: "Generating a token"
        String token = tokenProvider.generateToken("username", "saltValue", [role:"admin"])
        println "Generated token: ${token}"
        
        then: "The token is valid"
        token != null
        
        when: "Validating the token"
        Map data = tokenProvider.validateAndExtractToken(token)
        println "Extracted data: ${data}"
        
        then: "The data is correct"
        data.username == "username"
        data.salt == "saltValue"
        data.extradata.role == "admin"
    }
    
    void "test token with custom expiration"() {
        when: "Generating a token"
        String token = tokenProvider.generateTokenCustomExpiration("username", "saltValue", [role:"admin"], 120)
        println "Generated token: ${token}"
        
        then: "The token is valid"
        token != null
        
        when: "Validating the token"
        Map data = tokenProvider.validateAndExtractToken(token)
        println "Extracted data: ${data}"
        
        then: "The data is correct"
        data.username == "username"
        data.salt == "saltValue"
        data.extradata.role == "admin"
    }

    void "test token with no expiration"() {
        when: "Generating a token"
        String token = tokenProvider.generateTokenCustomExpiration("username", "saltValue", [role:"admin"], null)
        println "Generated token: ${token}"
        
        then: "The token is valid"
        token != null
        
        when: "Validating the token"
        Map data = tokenProvider.validateAndExtractToken(token)
        println "Extracted data: ${data}"
        
        then: "The data is correct"
        data.username == "username"
        data.salt == "saltValue"
        data.extradata.role == "admin"
    }

    void "test token with default expiration no salt"() {
        when: "Generating a token"
        String token = tokenProvider.generateToken("username", null, [role:"admin"])
        println "Generated token: ${token}"
        
        then: "The token is valid"
        token != null
        
        when: "Validating the token"
        Map data = tokenProvider.validateAndExtractToken(token)
        println "Extracted data: ${data}"
        
        then: "The data is correct"
        data.username == "username"
        data.extradata.role == "admin"
    }
    
    void "test token with custom expiration no salt"() {
        when: "Generating a token"
        String token = tokenProvider.generateTokenCustomExpiration("username", null, [role:"admin"], 120)
        println "Generated token: ${token}"
        
        then: "The token is valid"
        token != null
        
        when: "Validating the token"
        Map data = tokenProvider.validateAndExtractToken(token)
        println "Extracted data: ${data}"
        
        then: "The data is correct"
        data.username == "username"
        data.extradata.role == "admin"
    }

    void "test token with no expiration no salt"() {
        when: "Generating a token"
        String token = tokenProvider.generateTokenCustomExpiration("username", null, [role:"admin"], null)
        println "Generated token: ${token}"
        
        then: "The token is valid"
        token != null
        
        when: "Validating the token"
        Map data = tokenProvider.validateAndExtractToken(token)
        println "Extracted data: ${data}"
        
        then: "The data is correct"
        data.username == "username"
        data.extradata.role == "admin"
    }
}