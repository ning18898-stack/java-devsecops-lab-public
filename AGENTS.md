# Public snapshot workflow

只针对本项目本地 vulnerable-app 验证；不扫描公网。每项教学漏洞有 secure-app 修复及回归。
Java/Python 四空格，Vue/YAML 两空格。JDK17、Python3.11、Node24，固定依赖。
使用 docs/release/source-manifest.json 检查独立公开快照；不能要求或导入私有开发历史/标签。
核心回归断言不可删除。日志、凭据和原始输出仅写 ignored artifacts。
新提交身份须为维护者已核实的 GitHub 用户名/noreply；不能推算地址。
