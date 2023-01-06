## 插件说明

```
burpsuite插件
扩展burp suite自带的替换规则
根据edit_http_msg.config.yml中配置的规则替换通过burp模块的请求报文.

PS: 建议通过logger模块查看发送出去的最终报文记录.
```



## 规则示例

```
EXACT_REPLACE_RULE: "/-> /-> /admin.php"
含义：精确匹配替换
请求URI为【/】时，替换【 /】为【 /admin.php】

ROUGH_REPLACE_RULE: " /-> /admin.php/"
含义：粗略匹配替换
请求URI为【任意, 但不为/】时，替换【 /】为【 /admin.php/】

目前每种匹配方式仅支持单个规则.
```

