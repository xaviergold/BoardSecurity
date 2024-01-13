package com.board;

import javax.sql.DataSource;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

@Configuration
@PropertySource("classpath:/application.properties")
public class DataConfig {
	
	@Bean
	@ConfigurationProperties(prefix="spring.datasource.hikari")
	HikariConfig hikariConfig() {
		return new HikariConfig();
	}
	
	@Bean
	DataSource dataSource() {
		return new HikariDataSource(hikariConfig());
	}

}
