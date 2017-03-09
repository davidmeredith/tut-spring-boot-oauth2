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

import java.security.Principal;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class SocialApplication {
    public static void main(String[] args) {
        SpringApplication.run(SocialApplication.class, args);
    }
}

@Configuration
@EnableOAuth2Client
class RemoteResourceConfiguration {

    // @Bean
    // public OAuth2RestOperations restTemplate(OAuth2ClientContext oauth2ClientContext) {
    //   return new OAuth2RestTemplate(remote(), oauth2ClientContext);
    // }

    @Bean
    public OAuth2RestOperations oauth2RestTemplate(OAuth2ClientContext oauth2ClientContext,
            OAuth2ProtectedResourceDetails details) {
        return new OAuth2RestTemplate(details, oauth2ClientContext);
    }

}

@Configuration
@EnableOAuth2Sso
class UiMvcPortalConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.antMatcher("/**")
        .authorizeRequests()
          .antMatchers("/", "/login**", "/webjars/**").permitAll()
          
        .and()
          .authorizeRequests()
          .antMatchers("/injecttoken").hasRole("USER")
          
        .and()
           .authorizeRequests()
           .antMatchers("/admin").hasRole("ADMIN")
          
        .anyRequest().authenticated() // any other request must be authenticated 
        
        .and().logout().logoutSuccessUrl("/").permitAll().and().csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        // @formatter:on
    }

}

@RestController
class MyRestController {

    @Autowired
    TokenStore tokenStore;

    @Autowired
    OAuth2RestOperations oauth2RestTemplate;
    


    @RequestMapping("/user")
    public Principal user(Principal principal) {
        return principal;
    }

    @RequestMapping("/injecttoken")
    public Principal userWithRoleUser(OAuth2Authentication auth) {
        System.out.println(auth.getName());

        final OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
        // Note, can't directly inject the OAuth2AccessToken, it needs to be
        // extracted from OAuth2Authentication as above.
        OAuth2AccessToken token = tokenStore.readAccessToken(details.getTokenValue());
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
        System.out.println(resp);
        return auth;
    }

    @RequestMapping("/admin")
    public Principal admin(Principal principal) {
        return principal;
    }
}

/*
 package com.example;

import java.security.Principal;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@EnableOAuth2Sso
@EnableOAuth2Client
@RestController
public class SocialApplication extends WebSecurityConfigurerAdapter {
    
    @Autowired
    TokenStore tokenStore;
    
    @Autowired
    OAuth2RestOperations oauth2RestTemplate; 
    
    
    public static void main(String[] args) {
        SpringApplication.run(SocialApplication.class, args);
    }
    
    @Bean
    public OAuth2RestOperations oauth2RestTemplate(OAuth2ClientContext oauth2ClientContext,
            OAuth2ProtectedResourceDetails details) {
        return new OAuth2RestTemplate(details, oauth2ClientContext);
    }

    
    
    
    @RequestMapping("/user")
    public Principal user(Principal principal) {
        return principal;
    }
    
    

    @RequestMapping("/injecttoken")
    public Principal userWithRoleUser(OAuth2Authentication auth) {
        System.out.println(auth.getName()); 
        
        final OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
        // Note, can't directly inject the OAuth2AccessToken, it needs to be extracted from OAuth2Authentication as above.    
        OAuth2AccessToken token = tokenStore.readAccessToken(details.getTokenValue());
        Map<String, Object> map = token.getAdditionalInformation();
        Long accountId = Long.valueOf((Integer)map.get("accountId")); 
        System.out.println("accountId: ["+accountId+"]");
        
        //MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        //form.add("chat", "will it hurt?");
        String requestJson = "{\"chat\":\"will it hurt?\"}";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<String>(requestJson,headers);
        
        String resp = oauth2RestTemplate.postForEntity("https://alderheytest.eu-gb.mybluemix.net/api/v1/chat", entity, String.class ).getBody();
        System.out.println(resp); 
        return auth;
    }

    
    @RequestMapping("/admin")
    public Principal admin(Principal principal) {
        return principal;
    }

    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.antMatcher("/**")
        .authorizeRequests()
          .antMatchers("/", "/login**", "/webjars/**").permitAll()
          
        .and()
          .authorizeRequests()
          .antMatchers("/injecttoken").hasRole("USER")
          
            .and()
              .authorizeRequests()
              .antMatchers("/admin").hasRole("ADMIN")
          
        .anyRequest().authenticated()
        
        .and().logout().logoutSuccessUrl("/").permitAll().and().csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        // @formatter:on
    }



}
*/
