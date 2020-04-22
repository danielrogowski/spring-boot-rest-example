package com.droidablebee.springboot.rest.config;

import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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
    private static final Logger LOG = org.slf4j.LoggerFactory.getLogger(WebSecurityConfig.class);

    @Value("${security.userRead.name}")
    private String              userReadName;
    @Value("${security.userRead.pass}")
    private String              userReadPass;
    @Value("${security.userWrite.name}")
    private String              userWriteName;
    @Value("${security.userWrite.pass}")
    private String              userWritePass;

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String              issuerUri;

    @Value("${app.security.ignore:/swagger/**, /swagger-resources/**, /swagger-ui.html, /webjars/**, /v2/api-docs, /actuator/info}")
    private String[]            ignorePatterns;

    @Value("#{ROLE_USER_READ:USER_READ}")
    private String              roleUserRead;

    @Value("#{ROLE_USER_WRITE:USER_WRITE}")
    private String              roleUserWrite;

    @Bean
    public String roleUserRead(@Value("${ROLE_USER_READ:USER_READ}") final String roleUserRead) {
        return roleUserRead;
    }

    @Bean
    public String roleUserWrite(@Value("${ROLE_USER_WRITE:USER_WRITE}") final String roleUserWrite) {
        return roleUserWrite;
    }

//    @Bean(name = "ROLE_USER_READ")
//    public String roleUserRead() {
//        return ROLE_USER_READ;
//    }

//    @Bean(name = "ROLE_USER_WRITE")
//    public String roleUserWrite() {
//        return ROLE_USER_WRITE;
//    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        LOG.info("userReadName: {}", userReadName);
        LOG.info("userReadPass: {}", userReadPass);
        LOG.info("userWriteName: {}", userWriteName);
        LOG.info("userWritePass: {}", userWritePass);
        LOG.info("roleUserRead: {}", roleUserRead);
        LOG.info("roleUserWrite: {}", roleUserWrite);
        System.out.println("userWritePass: " + userWritePass);
        auth.inMemoryAuthentication()
                .withUser(userReadName)
                .password(userReadPass)
                .roles(roleUserRead)
                .and()
                .withUser(userWriteName)
                .password(userWritePass)
                .roles(roleUserWrite);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.csrf()
                .disable(); // do not require SCRF for POST and PUT

        http.authorizeRequests()
                // make sure principal is created for the health endpoint to verify the role
                .antMatchers("/actuator/health")
                .permitAll()
                .and()
                .authorizeRequests()
                .mvcMatchers(HttpMethod.PUT, "/v1/**")
                .hasAuthority(roleUserWrite)
                .and()
                .authorizeRequests()
                .mvcMatchers(HttpMethod.GET, "/v1/**")
                .hasAuthority(roleUserRead)
                .and()
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
    }

    @Override
    public void configure(WebSecurity web) {

        web.ignoring()
                .antMatchers(ignorePatterns);
    }

}
