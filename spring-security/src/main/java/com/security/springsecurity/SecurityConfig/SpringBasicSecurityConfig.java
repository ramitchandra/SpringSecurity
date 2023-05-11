package com.security.springsecurity.SecurityConfig;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class SpringBasicSecurityConfig {
	
	@Bean
	SecurityFilterChain myBasicSecurityChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//		http.formLogin();
		http.httpBasic();
		http.csrf().disable();
		http.headers().frameOptions().sameOrigin();
		return http.build();
	}
	
	/**
	 * Stores In-Memory
	 * @return
	 */
//	@Bean
//	public UserDetailsService userDetailService() {
//		var admin = User.withUsername("admin").password("{noop}root").roles("ADMIN").build();
//		var user = User.withUsername("user").password("{noop}root").roles("USER").build();
//		return new InMemoryUserDetailsManager(admin, user);
//	}
	
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder()
				.setType(EmbeddedDatabaseType.H2)
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
				.build();
	}
	
	@Bean
	public UserDetailsService userDetailService(DataSource dataSource) {
		
		var admin = User.withUsername("admin")
//				.password("{noop}root")
				.password("root")
				.passwordEncoder(pass -> passwordEncoder().encode(pass))
				.roles("ADMIN", "USER").build();
		var user = User.withUsername("user")
//				.password("{noop}root")
				.password("root")
				.passwordEncoder(pass -> passwordEncoder().encode(pass))
				.roles("USER").build();
		
		var manager = new JdbcUserDetailsManager(dataSource);
		manager.createUser(admin);
		manager.createUser(user);
		return manager;
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
