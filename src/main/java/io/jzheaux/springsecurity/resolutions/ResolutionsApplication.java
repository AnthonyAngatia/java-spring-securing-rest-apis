package io.jzheaux.springsecurity.resolutions;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import javax.sql.DataSource;
import java.util.List;

@SpringBootApplication
public class ResolutionsApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResolutionsApplication.class, args);
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
//        return new InMemoryUserDetailsManager(User.withUsername("user")
//                .password("{bcrypt}$2a$10$MywQEqdZFNIYnx.Ro/VQ0ulanQAl34B5xVjK2I/SDZNVGS5tHQ08W")
//                .authorities("resolution:read")
//                .build());
        return new JdbcUserDetailsManager(dataSource){
            @Override
            protected List<GrantedAuthority> loadUserAuthorities(String username) {
                return AuthorityUtils.createAuthorityList("resolution:read");
            }
        };
    }

}

