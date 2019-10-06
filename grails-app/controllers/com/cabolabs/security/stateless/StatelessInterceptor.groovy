package com.cabolabs.security.stateless

import net.kaleidos.grails.plugin.security.stateless.annotation.SecuredStateless
import net.kaleidos.grails.plugin.security.stateless.exception.StatelessValidationException
import groovy.json.JsonBuilder

class StatelessInterceptor {

   def statelessTokenProvider

   public StatelessInterceptor() {
      matchAll() //.excludes(controller:'auth') // FIXME: configurable controller name and action name for login on REST
   }

   boolean before() {

      log.debug "stateless interceptor before: c:'${controllerName}' a:'${actionName}'"

      if (!isSecuredStateless(controllerName, actionName, grailsApplication))
      {
         log.debug "not stateless secured"
         return true
      }
      log.debug "stateless secured"

      def authorization = request.getHeader("Authorization")
      def map
      try {
         map = statelessTokenProvider.validateAndExtractToken(authorization)
      } catch (StatelessValidationException e) {
         Closure getJsonErrorBytes = { String error ->
            Map errorMap = [message: error]
            String jsonMap = (new JsonBuilder(errorMap)).toString()
            return jsonMap.bytes
         }
         response.status = 401
         response.outputStream << getJsonErrorBytes(e.message)
         return false
      }

      if (map) {
         request.securityStatelessMap = map
         return true
      }
      response.status = 401
      return false
   }

   boolean after() { true }

   void afterView() {
        // no-op
   }

   // Checks if an action was annotated with SecuredStateless
   private boolean isSecuredStateless(String controllerName, String actionName, grailsApplication)
   {
      //println grailsApplication.getArtefacts("Controller") // []
      //println "isSecuredStateless controllers: "+ grailsApplication.controllerClasses.name.toString()
      //println "isSecuredStateless c: ${controllerName} a: ${actionName}" // null!

      // when accessing to root I don't get the name of the controller if an urlmapping is not defined!
      if (!controllerName) return false

      def controller = grailsApplication.controllerClasses.find{controllerName.toLowerCase() == it.name.toLowerCase()} //WordUtils.uncapitalize(it.name)}
      if (controller) {
         def clazz = controller.clazz
         if (clazz.isAnnotationPresent(SecuredStateless)) {
            return true
         }
         if (!actionName) {
            actionName = controller.defaultAction
         }
         def method = clazz.methods.find{actionName == it.name}
         if (method) {
            return method.isAnnotationPresent(SecuredStateless)
         }
      }
      return false
   }
}
