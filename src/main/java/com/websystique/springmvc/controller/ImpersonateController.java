package com.websystique.springmvc.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ImpersonateController {


    @RequestMapping(value = "/impersonate", method = RequestMethod.GET)
    public void impersonate(@RequestParam("username") String username, Authentication auth) {
        System.out.println("Impersonation: " + auth.getName());
    }
}
