package com.shiro.test.chapter3.permission;

import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.PermissionResolver;
import org.apache.shiro.authz.permission.WildcardPermission;

/**
 * Created by IntelliJ IDEA.
 * Creator : peng
 * Date : 2018-02-26
 * Time : 17:24
 */
public class BitAndWildPermissionResolver implements PermissionResolver {
    public Permission resolvePermission(String permissionString) {
        if(permissionString.startsWith("+")) {
            return new BitPermission(permissionString);
        }
        return new WildcardPermission(permissionString);
    }
}
