package com.droidablebee.springboot.rest.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    public static final String ROLE_NAME_USER_READ  = "USER_READ";
    public static final String ROLE_NAME_USER_WRITE = "USER_WRITE";

    @Value("${security.userRead.name}")
    private String             userReadName;
    @Value("${security.userRead.pass}")
    private String             userReadPass;
    @Value("${security.userWrite.name}")
    private String             userWriteName;
    @Value("${security.userWrite.pass}")
    private String             userWritePass;

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String             issuerUri;

    @Value("${app.security.ignore:/swagger/**, /swagger-resources/**, /swagger-ui.html, /webjars/**, /v2/api-docs, /actuator/info}")
    private String[]           ignorePatterns;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        System.out.println("userReadName: " + userReadName);
        System.out.println("userReadPass: " + userReadPass);
        System.out.println("userWriteName: " + userWriteName);
        System.out.println("userWritePass: " + userWritePass);
        auth.inMemoryAuthentication()
                .withUser(userReadName)
                .password(userReadPass)
                .roles(ROLE_NAME_USER_READ)
                .and()
                .withUser(userWriteName)
                .password(userWritePass)
                .roles(ROLE_NAME_USER_WRITE);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.csrf()
                .disable(); // do not require SCRF for POST and PUT

        // make sure principal is created for the health endpoint to verify the role
        http.authorizeRequests()
                .antMatchers("/actuator/health")
                .permitAll();

        // die brauche ich nicht, weil ich es direkt im Controller auf Ebene der Methode
        // mache
        http.authorizeRequests()
//                .mvcMatchers(HttpMethod.PUT, "/v1/person**")
//                .hasAuthority(ROLE_NAME_USER_WRITE)
                .anyRequest()
                .authenticated()
                .and()
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

//        http.authorizeRequests()
////                .mvcMatchers(HttpMethod.GET, "/v1/person**")
////                .hasAuthority(ROLE_NAME_USER_READ)
//                .anyRequest()
//                .authenticated()
//                .and()
//                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
    }

    @Override
    public void configure(WebSecurity web) {

        web.ignoring()
                .antMatchers(ignorePatterns);
    }

}
