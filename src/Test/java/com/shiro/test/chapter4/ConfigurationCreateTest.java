package com.shiro.test.chapter4;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Assert;
import org.junit.Test;

/**
 * Created by IntelliJ IDEA.
 * Creator : peng
 * Date : 2018-02-28
 * Time : 12:43
 */
public class ConfigurationCreateTest {
    @Test
    public void testConfiguration(){
        Factory<SecurityManager> factory =
                new IniSecurityManagerFactory("classpath:shiro-config.ini");
        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
        //将SecurityManager设置到SecurityUtils 方便全局使用
        SecurityUtils.setSecurityManager(securityManager);
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
        subject.login(token);
        Assert.assertTrue(subject.isAuthenticated());

    }
}
