package grails.security.stateless.ng

import grails.plugins.*
import net.kaleidos.grails.plugin.security.stateless.*
import net.kaleidos.grails.plugin.security.stateless.token.*

import groovy.util.logging.Slf4j

@Slf4j
class GrailsSecurityStatelessNgGrailsPlugin extends Plugin {

    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "3.3.9 > *"
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
        "grails-app/views/error.gsp"
    ]

    // TODO Fill in these fields
    def title = "Grails Security Stateless NG" // Headline display name of the plugin
    def author = "Pablo Pazos"
    def authorEmail = "pablo.pazos@cabolabs.com"
    def description = '''\
Grails Security Stateless for Grails 3
'''
    def profiles = ['web']

    // URL to the plugin's documentation
    def documentation = "http://grails.org/plugin/grails-security-stateless-ng"

    // Extra (optional) plugin metadata

    // License: one of 'APACHE', 'GPL2', 'GPL3'
//    def license = "APACHE"

    // Details of company behind the plugin (if there is one)
//    def organization = [ name: "My Company", url: "http://www.my-company.com/" ]

    // Any additional developers beyond the author specified above.
//    def developers = [ [ name: "Joe Bloggs", email: "joe@bloggs.net" ]]

    // Location of the plugin's issue tracker.
//    def issueManagement = [ system: "JIRA", url: "http://jira.grails.org/browse/GPMYPLUGIN" ]

    // Online location of the plugin's browseable source code.
//    def scm = [ url: "http://svn.codehaus.org/grails-plugins/" ]

   Closure doWithSpring() { {->
         // classes that can be injected
         cryptoService(CryptoService)
         statelessTokenProvider(JwtStatelessTokenProvider) {
            cryptoService = ref("cryptoService")
         }
         //statelessTokenValidator(StatelessTokenValidator)

      }
   }

   void doWithDynamicMethods() {
      // Implement registering dynamic methods to classes (optional)

      def conf = applicationContext.grailsApplication.config.stateless

      // log.info conf.secretKey
      // log.info conf.expirationTime.toString()
      //
      // println "++++++++ "+ applicationContext.statelessTokenProvider
      // println "************* " + conf.secretKey
      //throw new Exception(conf.secretKey)

      // configuration!
      // check https://github.com/kaleidos/grails-security-stateless/blob/a35fe41b78c805fae841146973e4b4d9ae563388/SecurityStatelessGrailsPlugin.groovy#L152
      applicationContext.cryptoService.init(conf.secretKey)
      if (conf.expirationTime) {
         //applicationContext.statelessTokenValidator.init(new Integer(conf.expirationTime))
         applicationContext.statelessTokenProvider.init(new Integer(conf.expirationTime))
      }
   }

    void doWithApplicationContext() {
        // TODO Implement post initialization spring config (optional)
    }

    void onChange(Map<String, Object> event) {
        // TODO Implement code that is executed when any artefact that this plugin is
        // watching is modified and reloaded. The event contains: event.source,
        // event.application, event.manager, event.ctx, and event.plugin.
    }

    void onConfigChange(Map<String, Object> event) {
        // TODO Implement code that is executed when the project configuration changes.
        // The event is the same as for 'onChange'.
    }

    void onShutdown(Map<String, Object> event) {
        // TODO Implement code that is executed when the application shuts down (optional)
    }
}
