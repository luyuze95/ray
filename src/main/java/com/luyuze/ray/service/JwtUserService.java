package com.luyuze.ray.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Date;

public class JwtUserService implements UserDetailsService {

    private PasswordEncoder passwordEncoder;

    public JwtUserService() {
        this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 真实系统需要从数据库或者缓存中获取，这里对密码做了密码
        return User
                .builder()
                .username("luyuze")
                .password(passwordEncoder.encode("luyuze-password"))
                .roles("USER")
                .build();
    }

    public UserDetails getUserLoginInfo(String username) {
        String salt = "123456ef";
        /**
         * 从数据库或者缓存中取出 jwt token 生成时用的salt
         * salt = redisTemplate.opsForValue().get("token" + username);
         */
        UserDetails user = loadUserByUsername(username);
        // 将salt放到password字段返回
        return User
                .builder()
                .username(user.getUsername())
                .password(salt)
                .authorities(user.getAuthorities())
                .build();
    }

    public String saveUserLoginInfo(UserDetails user) {
        String salt = "123456ef"; // BCrypt.gensalt(); 正式开发时可以调用此方法实时生成加密的salt
        /**
         * 将salt保存到数据库或缓存中
         * redisTemplate.opsForValue().set("token" + username, salt, 3600, TimeUnit.SECONDS);
         */
        Algorithm algorithm = Algorithm.HMAC256(salt);
        Date date = new Date(System.currentTimeMillis() + 3600 * 1000); // 设置1小时后过期
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(date)
                .withIssuedAt(new Date())
                .sign(algorithm);
    }

    public void createUser(String username, String password) {
        String encryptPwd = passwordEncoder.encode(password);
        // 保存用户名和加密后密码到数据库
    }

    public void deleteUserLoginInfo(String username) {
        // 清除数据库或者缓存中登陆salt
    }
}
