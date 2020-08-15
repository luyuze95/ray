package com.luyuze.ray.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("article")
public class ArticleController {

    @GetMapping("{id}")
    public String load(@PathVariable Long id) {
        return "this is my first blog";
    }

    @PostMapping("add")
    public void create(@AuthenticationPrincipal UserDetails user) {
    }
}
