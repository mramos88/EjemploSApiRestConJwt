package com.javainuse.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.javainuse.dao.UserDao;
import com.javainuse.model.Usuario;
import com.javainuse.model.UserDTO;

@Service
public class JwtUserDetailsService implements UserDetailsService {
	
	@Autowired
	private UserDao userDao;

	@Autowired
	private PasswordEncoder bcryptEncoder;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		//consultamos a la base de datos por el nombre de usuario. Si existe intentamos el login 
		Usuario user = userDao.findByUsername(username);
		if (user == null) {
			throw new UsernameNotFoundException("User not found with username: " + username);
		}
		

		List<GrantedAuthority> roles = new ArrayList<>();
		if(username=="admin") {
			roles.add(new SimpleGrantedAuthority("admin"));	
			
		}
		
		//Pasamos usuario y pass como nos llega de la peticion. La encriptacion y validacion 
		return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),roles
				);
	}
	
	public Usuario save(UserDTO user) {
		Usuario newUser = new Usuario();
		newUser.setUsername(user.getUsername());
		newUser.setPassword(bcryptEncoder.encode(user.getPassword()));
		return userDao.save(newUser);
	}
}