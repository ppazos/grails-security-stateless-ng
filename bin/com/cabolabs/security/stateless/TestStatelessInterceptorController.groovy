package com.cabolabs.security.stateless

import net.kaleidos.grails.plugin.security.stateless.annotation.SecuredStateless

class TestStatelessInterceptorController {

   def notSecuredStateless()
   {
      render "action response"
   }

   @SecuredStateless
   def securedStateless()
   {
      render "action response"
   }
}
