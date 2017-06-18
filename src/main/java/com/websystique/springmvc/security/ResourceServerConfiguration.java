package com.websystique.springmvc.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

import com.websystique.springmvc.configuration.CORSFilter;
import com.websystique.springmvc.impersonation.ImpersonationFilter;

@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

	private static final String RESOURCE_ID = "my_rest_api";
	
	@Override
	public void configure(ResourceServerSecurityConfigurer resources) {
		resources.resourceId(RESOURCE_ID).stateless(false);
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http
		.anonymous().disable()
		.requestMatchers().antMatchers("/**")
		.and()
		.authorizeRequests()
		.antMatchers("/**").authenticated()
		.and()
		.exceptionHandling().accessDeniedHandler(new OAuth2AccessDeniedHandler())
		.and().addFilterAfter(new ImpersonationFilter(), FilterSecurityInterceptor.class)
		;
	}

}