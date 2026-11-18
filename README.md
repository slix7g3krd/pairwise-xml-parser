# pairwise-xml-parser

第三方 XML 订单一接入，解析器就把内网暴露了：默认允许 DTD，外部实体能读 /etc/passwd；参数实体和 XInclude 没有关闭；实体展开不设上限，billion laughs 直接打满内存；schemaLocation 指向内网地址，解析时发起 SSRF；命名空间校验只看 localName，伪造前缀能绕过；DOCTYPE 里的 SYSTEM 标识符没有拒绝；解析错误把文件内容带进响应；外部 DTD 超时没有设置；实体递归深度不限制；XPath 查询拼接用户输入，能注入谓词；CDATA 里的实体不转义；编码声明和实际字节不一致；解析器复用后实体缓存残留；大文档不限制大小。security/xml_parser.py 是核心，tests/test_xml_parser.py 15个红。要修的是：禁用 DTD；禁用外部实体；禁用 XInclude；实体展开上限；schema 地址白名单；命名空间全名校验；拒绝 SYSTEM；错误脱敏；外部 DTD 超时；递归深度；XPath 参数化；CDATA 处理；编码校验；解析器不复用；文档大小限制。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
