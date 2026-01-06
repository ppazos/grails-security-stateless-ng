package net.kaleidos.grails.plugin.security.stateless.token

interface StatelessTokenProvider {
    void init(Integer expirationTime)
    String generateToken(String userName, String salt, Map<String,String> extraData)
    String generateTokenCustomExpiration(String userName, String salt, Map<String,String> extraData, Integer customExpirationTime)
    Map validateAndExtractToken(String token)
}