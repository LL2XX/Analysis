# Shiro权限绕过系列漏洞复现及分析
## 漏洞背景
### Shiro过滤器
Shiro框架通过过滤器功能来对用户访问权限进行控制，如anon, authc等过滤器。anon为匿名过滤器，不需要登录即可访问；authc为登录过滤器，需要登录才可以访问，可通过ShiroFilterFactoryBean类进行配置
> Shiro的URL路径表达式为ANT格式，路径通配符支持 ? * ** 
> ?：匹配一个字符
> *：匹配零个或多个字符串
> **：匹配路径中的零个或多个路径

![]()

用户发起请求时，Shiro过滤器会先于Web框架对请求进行处理，首先Shiro会通过PathMatchingFilterChainResolver#getChain函数，将用户请求url和配置中的路径进行匹配，获取对应的过滤器，漏洞成因即为该处路径匹配
![]()

### Spring MVC控制器
Spring通过控制器管理不同url的返回内容，可通过注解配置
![]()

Spring前端控制器的DispatcherServlet#doDispatch方法在执行时，会先获取Handler，其中包括控制器和拦截器，同样是通过路径匹配方式，正是前后对于url处理和匹配的不一致，导致了漏洞的产生
![]()

## CVE-2020-1957
### 漏洞原理
官方在[文档](https://issues.apache.org/jira/browse/SHIRO-682)中详细描述了漏洞产生原，在 Spring Web 中，requestURI: /resource/menus 和 /resource/menus/ 都可以访问资源， 但Shiro的路径模式匹配/resource/menus无法匹配/resource/menus/用户可以使用 requestURI +“/”来简单地绕过链式过滤器，从而绕过 shiro 保护

### 漏洞复现
> 影响版本：Apache Shiro ≤1.5.2

下载[demo代码](https://github.com/xhycccc/Shiro-Vuln-Demo/tree/main/shiro_cve-2020-1957)，导入idea，maven自动加载依赖即可使用
过滤器配置为/hello/*路径需认证
![]()

开启服务，访问/hello/1，返回302，跳转至/login
![]()

访问/hello/1/，返回hello，成功绕过
![]()

### 漏洞分析
Shiro过滤器会进行路径匹配，其中AntPathMatcher#doMatch方法在执行时，首先会将配置路径和请求路径根据‘/’进行分割，/hello/*拆分为hello和*，/hello/1/拆分为hello和1，*可匹配任意字符，第一步匹配成功
![]()

随后会检查路径长度，发现长度不匹配时，例子中/hello/1/比/hello/*多了一个‘/’，此时，会检查请求路径以及配置路径是否以‘/’结尾，当配置路径/hello/*不以‘/’结尾，而请求路径/hello/1/以‘/’结尾时，匹配会返回false，造成过滤器被绕过
![]()

而Spring在获取handle时，也会进行路径匹配，它的做法仍是会将url根据‘/’分割，当分割后的字符串匹配但url长度不匹配时，会判断请求是否以‘/’结尾，若是，则仍能匹配成功，Spring和Shiro之间路径匹配的不一致最终导致了权限绕过漏洞
![]()

### 漏洞修复
在执行路径匹配之前PathMatchingFilterChainResolver#getChain方法中加入对结尾‘/’的判断，删去结尾‘/’
![]()

## CVE-2020-11989
### 漏洞原理
在1.5.2版本，Shiro过滤器解析url时会因为分号截断，Web框架却能解析出分号后面的路径，Shiro过滤器获取到错误的url，造成绕过

### 漏洞复现
下载[demo代码](https://github.com/xhycccc/Shiro-Vuln-Demo/tree/main/shiro_cve-2020-11989)，导入idea，maven自动加载依赖即可使用
过滤器配置为/admin/* 需要登录
![]()

控制器响应/admin/page
![]()

开启服务，访问/admin/page，302跳转至/login
![]()

访问/;/admin/page，返回admin page，成功绕过
![]()

### 漏洞分析
> 利用条件
> - Apache Shiro < 1.5.3
> - Spring 框架中只使用 Shiro 鉴权
> - 配置文件中设定了特定的context-path

Shiro通过url匹配获取过滤器，在PathMatchingFilterChainResolver#getChain方法中，通过getPathWithinApplication()函数解析请求url
![]()

获取contextPath会首先从配置中获取，配置中若为空，再根据请求获取，只要请求开头为‘/’，则contextPath为空
![]()

获取requestUri时会将请求url进行一般化处理，由于分号截断，获得的uri会只剩下‘/’，最后就将/;/admin/page解析成了/，绕过过滤器/admin/*
![]()

Spring在获取handle时，会将/;/admin/page解析为/admin/page，匹配到对应控制器，造成权限绕过

### 漏洞修复
重写了解析url的getPathWithinApplication方法，通过PathInfo和ServletPath拼接，并去除分号
![]()

## CVE-2020-13933
### 漏洞原理
getServletPath会对%3b进行解码，即/test/admin/%3bxxx会变为/admin/;xxx，再经过removeSemicolon函数进行处理，醉的返回的URI为/admin/，由于*无法匹配路径，因此在pathMatches函数中会返回false，导致权限校验被绕过

### 漏洞复现
下载[demo代码](https://github.com/xhycccc/Shiro-Vuln-Demo/tree/main/shiro_cve-2020-13933)，导入idea，maven自动加载依赖即可使用

过滤器配置为/admin/*
![]()

开启服务，访问/admin/page，跳转
![]()

访问/admin/%3bpage，绕过
![]()

### 漏洞分析
进入getPathWithinApplication函数
![]()

首先进行getServletPath解析，在该函数中，使用的uri是经过了uri解码后的，使得/admin/%3bpage被解析为/admin/;page
![]()

Pathinfo为空，拼接得到/admin/;page，再经过分号截断，得到/admin/
![]()

最后再经过CVE-2020-1957补丁增加的删去最后一个‘/’的操作，得到/admin，该url可以匹配/\*和/admin/\*\*，但不能匹配/admin/\*，造成绕过
![]()

### 漏洞修复
在 1.6.0版本的修复中，针对/*这种ant风格的配置出现的问题，shiro在org.apache.shiro.spring.web.ShiroFilterFactoryBean.java中默认增加了/**的路径配置，以防止出现匹配不成功的情况。

## 总结
Shiro权限绕过漏洞产生的原因主要都是Spring和Shiro对于url解析的差异导致的，其中又包括了对特殊符号的处理策略，参数编码问题，对于同一内容的不同处理策略就可能导致多种漏洞的产生，不同框架间在同一功能的差异性是在测试时需要注意的方面
