/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;

/**
 * Bootable main class. App can run either as a executable war with an embedded tomcat, or as 
 * a regular .war without the embedded tomcat (target/socialXXX-.war.original). To build both, 
 * the main bootable class has to extend SpringBootServletInitializer (see pom.xml for details). 
 * 
 * @author David Meredith david.meredith@stfc.ac.uk
 *
 */
@SpringBootApplication // equivalent to declaring @Configuration, @EnableAutoConfiguration and @ComponentScan
public class SocialApplication extends SpringBootServletInitializer {
    public static void main(String[] args) {
        // main is only called when running with an embedded tomcat. 
        SpringApplication.run(SocialApplication.class, args);
    }
    
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        // called when running as a regualar war (.war.original) 
        return application.sources(SocialApplication.class);
    }
}

/**
 * Main configuration/application class. 
 * The @EnableOAuth2Sso isn't used in this sample as it wasn't designed to support 
 * multiple providers using simple app.props/YAML declarations. Instead of using 
 * that you need to install separate OAuth2AuthenticationProcessingFilters in your 
 * security configuration, each with a different login path, and then link to them from a UI.
 * This is shown in this class.  
 * @see http://stackoverflow.com/questions/33512401/enableoauth2sso-simultaneously-for-multiple-social-networks
 * 
 * @author David Meredith david.meredith@stfc.ac.uk
 *
 */
@Configuration 
@RestController
@EnableOAuth2Client
// @EnableAuthorizationServer
@Order(6)
class MainConfig extends  WebSecurityConfigurerAdapter{
   
    /**
     * Injected by boot. 
     */
    @Autowired
    OAuth2ClientContext oauth2ClientContext;
    
    /**
     * Used just for successful authentication against AH Auth server. 
     */
    @Autowired
    AlderHeyAuthenticationSuccessHandler alderHeyAuthenticationSuccessHandler; 
    
    /**
     * RestTemplate bean which can be injected as needed and can be used to 
     * invoke configured OAuth2 resource servers. 
     * 
     * @param oauth2ClientContext
     * @param details
     * @return
     */
    @Bean
    public OAuth2RestOperations oauth2RestTemplate(OAuth2ClientContext oauth2ClientContext, 
            OAuth2ProtectedResourceDetails details) {
        return new OAuth2RestTemplate(details, oauth2ClientContext);
    }

//    @RequestMapping({ "/user", "/me" })
//    public Map<String, String> user(Principal principal) {
//        Map<String, String> map = new LinkedHashMap<>();
//        map.put("name", principal.getName());
//        return map;
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
		http.antMatcher("/**")
		.authorizeRequests()
		   .antMatchers("/", "/login**", "/webjars/**").permitAll()
		   
	        .and()
	           .authorizeRequests()
	           .antMatchers("/admin").hasRole("ADMIN")  
		  
		   .anyRequest().authenticated() // any other request must be authenticated 
				
			.and().exceptionHandling()
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
			
			.and().logout().logoutSuccessUrl("/").permitAll()
			.and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
				
			.and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
		// @formatter:on
    }

    // @Configuration
    // @EnableResourceServer
    // protected static class ResourceServerConfiguration extends
    // ResourceServerConfigurerAdapter {
    // @Override
    // public void configure(HttpSecurity http) throws Exception {
//			// @formatter:off
//			http.antMatcher("/me").authorizeRequests().anyRequest().authenticated();
//			// @formatter:on
    // }
    // }

 

    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }

    @Bean
    @ConfigurationProperties("github")
    public ClientResources github() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("facebook")
    public ClientResources facebook() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("alderhey")
    public ClientResources alderhey() {
        return new ClientResources();
    }

    private Filter ssoFilter() {
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();
        filters.add(ssoFilterOAuth2AuthorisationCodeFlowFilter(facebook(), "/login/facebook"));
        filters.add(ssoFilterOAuth2AuthorisationCodeFlowFilter(github(), "/login/github"));
        filters.add(ssoAlderHeyAuthorisationCodeJwtFilter(alderhey(), "/login/alderhey"));
        filter.setFilters(filters);
        return filter;
    }

    /**
     * Builds an AuthenticationProcessing Filter that supports the standard OAuth2 Authorisation code flow, e.g. 
     * for GitHub and Facebook. The filter will invoke the configured accessTokenUri to 
     * fetch a token and then use the token to invoke the userInfoUri to fetch extra auth
     * details/claims about the user, e.g. '/me' in FB. 
     *  
     * @param client
     * @param path
     * @return
     */
    private Filter ssoFilterOAuth2AuthorisationCodeFlowFilter(ClientResources client, String path) {
        OAuth2ClientAuthenticationProcessingFilter oAuth2ClientAuthenticationFilter = 
                new OAuth2ClientAuthenticationProcessingFilter(path);
        
        // Set a restTemplate so the authFilter can call the accessTokenUri in order to fetch access token 
        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
        oAuth2ClientAuthenticationFilter.setRestTemplate(oAuth2RestTemplate);
        
        
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(client.getResource().getUserInfoUri(),
                client.getClient().getClientId());
        // set restTemplate to call the userInfoUri to get extra auth details about the user
        tokenServices.setRestTemplate(oAuth2RestTemplate);
        
        oAuth2ClientAuthenticationFilter.setTokenServices(tokenServices);
        return oAuth2ClientAuthenticationFilter;
    }
    


    /**
     * Builds an AuthenticationProcessing Filter that supports the OAuth2 Authorisation code flow 
     * that returns a JWT. In this flow we don't invoke the auth server's userInfoUri to get extra auth details/claims
     * about the user because these details are encoded directly into the JWT as custom claims. 
     *  
     * @param client
     * @param path
     * @return
     */
    private Filter ssoAlderHeyAuthorisationCodeJwtFilter(ClientResources client, String path) {
        OAuth2ClientAuthenticationProcessingFilter alderHeyOAuth2ClientAuthenticationFilter = 
                new OAuth2ClientAuthenticationProcessingFilter(path);

        // RestTemplate needed to contact the accessTokenUri in order to fetch the access token 
        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
        alderHeyOAuth2ClientAuthenticationFilter.setRestTemplate(oAuth2RestTemplate);


        DefaultTokenServices alderHeyTokenServices = alderHeyTokenServices();
        // We don't need to do 'alderHeyTokenServices.setRestTemplate(oAuth2RestTemplate)' for the alderHey clientAuthFilter 
        // because we are using JWT - the userInfoUri is not called with JWT,  
        // instead claims are encoded into the token so no callback is needed here.  
        alderHeyOAuth2ClientAuthenticationFilter.setTokenServices(alderHeyTokenServices);

        // A Custom Auth Success Handler
        alderHeyOAuth2ClientAuthenticationFilter.setAuthenticationSuccessHandler(alderHeyAuthenticationSuccessHandler);

        // OR could maybe do this using a Bean post processor
        /*
         * public static class DefaultRolesPrefixPostProcessor implements
         * BeanPostProcessor, PriorityOrdered {
         * 
         * @Override public Object postProcessAfterInitialization(Object bean,
         * String beanName) throws BeansException { if (bean instanceof
         * FilterChainProxy) {
         * 
         * FilterChainProxy chains = (FilterChainProxy) bean;
         * 
         * for (SecurityFilterChain chain : chains.getFilterChains()) { for
         * (Filter filter : chain.getFilters()) { if (filter instanceof
         * OAuth2ClientAuthenticationProcessingFilter) {
         * OAuth2ClientAuthenticationProcessingFilter
         * oAuth2ClientAuthenticationProcessingFilter =
         * (OAuth2ClientAuthenticationProcessingFilter) filter;
         * oAuth2ClientAuthenticationProcessingFilter
         * .setAuthenticationSuccessHandler(customAuthenticationSuccessHandler()
         * ); } } } } return bean; } }
         */

        return alderHeyOAuth2ClientAuthenticationFilter;
    }

    
    @Primary 
    @Bean
    public DefaultTokenServices alderHeyTokenServices() {
        // Need to either declare this as a @Primary @Bean or don't declare this TokenServices instance as a bean. 
        // If declared as a @Bean without @Primary, then we get the following exception/failure below. 
        // I think this is because this class defines @EnableOAuth2Client which autoconfigures a TokenServices 
        // instance for us, so we therefore have two instances available for injection. 
        // We may not actually need to declare this TokenServices as Bean because we can use the alderHeyTokenStore 
        // Bean to read the JWT and fetch the custom claims. 
        /* 
        ***************************
        APPLICATION FAILED TO START
        ***************************
        Description:
        Method springSecurityFilterChain in org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration required a single bean, but 2 were found:
                - remoteTokenServices: defined by method 'remoteTokenServices' in class path resource [org/springframework/boot/autoconfigure/security/oauth2/resource/ResourceServerTokenServicesConfiguration$RemoteTokenServicesConfiguration$TokenInfoServicesConfiguration.class]
                - alderHeyTokenServices: defined by method 'alderHeyTokenServices' in com.example.SocialApplication

        Action:
        Consider marking one of the beans as @Primary, updating the consumer to accept multiple beans, or using @Qualifier to identify the bean that should be consumed
        
        Caused by: org.springframework.beans.factory.NoUniqueBeanDefinitionException: No qualifying bean of type 'org.springframework.security.oauth2.provider.token.ResourceServerTokenServices' available: expected single matching bean but found 2: remoteTokenServices,alderHeyTokenServices

        */
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(alderHeyTokenStore());
        return defaultTokenServices;
    }

    @Bean()
    public TokenStore alderHeyTokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        // this needs to be a bean, otherwise we get:
        // uth2ClientAuthenticationProcessingFilter : Authentication request failed: org.springframework.security.authentication.BadCredentialsException: Could not obtain user details from token
        //org.springframework.security.authentication.BadCredentialsException: Could not obtain user details from token

        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        String publicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnGp/Q5lh0P8nPL21oMMrt2RrkT9AW5jgYwLfSUnJVc9G6uR3cXRRDCjHqWU5WYwivcF180A6CWp/ireQFFBNowgc5XaA0kPpzEtgsA5YsNX7iSnUibB004iBTfU9hZ2Rbsc8cWqynT0RyN4TP1RYVSeVKvMQk4GT1r7JCEC+TNu1ELmbNwMQyzKjsfBXyIOCFU/E94ktvsTZUHF4Oq44DBylCDsS1k7/sfZC2G5EU7Oz0mhG8+Uz6MSEQHtoIi6mc8u64Rwi3Z3tscuWG2ShtsUFuNSAFNkY7LkLn+/hxLCu2bNISMaESa8dG22CIMuIeRLVcAmEWEWH5EEforTg+QIDAQAB\n"
                + "-----END PUBLIC KEY-----\n";
        converter.setVerifierKey(publicKey);
        // or if using a symetric key
        // converter.setSigningKey("123");
        return converter;
        /*
         * Resource resource = new ClassPathResource("public.txt"); String
         * publicKey = null; try { publicKey =
         * IOUtils.toString(resource.getInputStream()); } catch (final
         * IOException e) { throw new RuntimeException(e); }
         * converter.setVerifierKey(publicKey); return converter;
         */
    }

}

class ClientResources {

    @NestedConfigurationProperty
    private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

    @NestedConfigurationProperty
    private ResourceServerProperties resource = new ResourceServerProperties();

    public AuthorizationCodeResourceDetails getClient() {
        return client;
    }

    public ResourceServerProperties getResource() {
        return resource;
    }
}

@Component
class AlderHeyAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication auth) throws ServletException, IOException {
        // This class is responsible for performing the redirect to the original URL if appropriate - 
        // useful for OAuth2 client so the OAuth2 dance is completed correctly. If you implemented a 
        // standard AuthenticationSuccessHandler then you would need to control subsequent 
        // navigation using a redirect or a forward, here we can call super.onAuthenticationSuccess(...) 
        // to continue with the saved request. Note, you still have the option to re-direct to a 
        // different page, e.g. consider if a password change is needed: 
        //if(passChangeRequired) {
            // start "change password" flow:
            //log.info("password expired for user " + username);
            //String encUser = cryptoService.generateEncodedString(username);
            // redirect to a set new password page:
            //response.sendRedirect( FlowsConstatns.LOGIN_FORMS_DIR + "/changePassword.jsp?username=" + username + 
            //        "&" + FlowsConstatns.HASH_PARAM_NAME + "=" + encUser);
            //return;
         //}
        System.out.println("*******************AlderHey login ["+auth.getName()+"]**************************");
        super.onAuthenticationSuccess(request, response, auth);
    }
}

/*@Component
class AlderHeyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication auth)
            throws IOException, ServletException {
        // Implementations can do whatever they want but typical behaviour would
        // be to control the navigation to the subsequent destination (using a
        // redirect or a forward). For example, after a user has logged in by
        // submitting a login form, the application needs to decide where they
        // should be redirected to afterwards (see
        // AbstractAuthenticationProcessingFilter and subclasses). Other logic
        // may also be included if required.
        System.out.println("*******************AlderHey login ["+auth.getName()+"]**************************"); 
        // here need 
    }
}*/


@RestController
class MyRestController {

    @Autowired
    TokenStore alderHeyTokenStore;

    @Autowired
    OAuth2RestOperations oauth2RestTemplate;
    


    @RequestMapping("/user")
    public Principal user(Principal principal) {
        return principal;
    }

    // No need to return the OAuth2Authentication, it implements  
    // java.security.Principal 
//    @RequestMapping("/oauth2Authentication")
//    public OAuth2Authentication getOAuth2Authentication(OAuth2Authentication auth) {    
//        return auth;
//    }

    @RequestMapping("/invokeAlderHeyAPI")
    public String userWithRoleUser(OAuth2Authentication auth) {
        // An OAuth 2 authentication token can contain two authentications: one for the client and one for the user. 
        // Since some OAuth authorization grants don't require user authentication, the user authentication may be null.
        System.out.println(auth.getName());

        final OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
        // Note, can't directly inject the OAuth2AccessToken, it needs to be
        // extracted from OAuth2Authentication as above.
        OAuth2AccessToken token = alderHeyTokenStore.readAccessToken(details.getTokenValue());
        Map<String, Object> map = token.getAdditionalInformation();
        Long accountId = Long.valueOf((Integer) map.get("accountId"));
        System.out.println("accountId: [" + accountId + "]");

        // MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        // form.add("chat", "will it hurt?");
        String requestJson = "{\"chat\":\"will it hurt?\"}";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<String>(requestJson, headers);

        String resp = oauth2RestTemplate
                .postForEntity("https://alderheytest.eu-gb.mybluemix.net/api/v1/chat", entity, String.class).getBody();
        //System.out.println(resp);
        //return auth;
        return resp; 
    }

    @RequestMapping("/admin")
    public Principal admin(Principal principal) {
        return principal;
    }
}
