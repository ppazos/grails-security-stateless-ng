package com.cabolabs.security.stateless

import grails.testing.mixin.integration.Integration
//import grails.transaction.*
import spock.lang.Specification

@Integration
//@Rollback
class TestPluginSpec extends Specification {

   def setup() {
   }

   def cleanup() {
   }

   void "test something"() {
      expect:"fix me"
         true == true
   }
}
