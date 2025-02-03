package com.jb.securityservice.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class TestRestApi {

    @GetMapping
    public Map<String,Object> dataTest(){
        return Map.of("message","Data Test");
    }
}
