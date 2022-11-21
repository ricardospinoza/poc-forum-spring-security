package br.com.alura.forum.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
@Configuration
public class SecurityConfigurations extends WebSecurityConfigurerAdapter{

	@Autowired
	private AutenticacaoService autenticacaoService;
	
	@Override
	@Bean
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		//configurar a autenticação
		auth.userDetailsService(autenticacaoService).passwordEncoder(new BCryptPasswordEncoder());
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//Configuração de autorização, parte de url, perfil de acesso
		http.authorizeRequests()
		//liberando acesso publico a listagem topicos e topicos/{id}, demais nega acesso publico
		.antMatchers(HttpMethod.GET, "/topicos").permitAll()
		.antMatchers(HttpMethod.GET, "/topicos/*").permitAll()
		.antMatchers(HttpMethod.POST, "/auth").permitAll()
		//--
		.anyRequest().authenticated()
		.and().csrf().disable() //desabilita tipo de ataque pq vamos usar autenticação de token e não precisa o spring ver isto
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		;
		
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		//Configurações de recursos estaticos, requisiçõesp para arquivos, javascript, imagens, etc.. para o frontend 
	}
	
	
//	public static void main(String[] args) {
//		System.out.println(new BCryptPasswordEncoder().encode("123456"));
//	}
}