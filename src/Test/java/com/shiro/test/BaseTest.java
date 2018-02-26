package com.shiro.test;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;

/**
 * Created by IntelliJ IDEA.
 * Creator : peng
 * Date : 2018-02-26
 * Time : 16:22
 */
public abstract class BaseTest {
    public void login(String configFile, String userName, String password) {
        //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory factory =
                new IniSecurityManagerFactory(configFile);
        //2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = (SecurityManager) factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
        subject.login(token);
    }

    public Subject subject(){
        return SecurityUtils.getSubject();
    }
}
