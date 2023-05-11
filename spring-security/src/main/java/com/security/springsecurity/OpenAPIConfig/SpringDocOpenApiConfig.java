package com.security.springsecurity.OpenAPIConfig;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;

@Configuration
public class SpringDocOpenApiConfig {
	
	@Bean
    public OpenAPI usersMicroserviceOpenAPI() {
        return new OpenAPI()
                .info(new Info().title("Spring Security")
                                 .description("Implementation of Spring Security")
                                 .version("1.0"));
	}

}
