U3D游戏global-metadata.dat加密，根据global-metadata.dat头部特征，从内存中抠取。  

- new_metadata_dump.js：新版本的脚本，推荐使用。
- global-metadata_dump.js：原版本，可学习研究。

# 使用方法
1、启动手机的 frida 服务。  
2、在js文件的存放目录下，右键，打开PowerShell。  
3、启动游戏（建议游戏进入了主场景之类的再继续后续）。  
4、执行以下命令行：  
**frida -U -l global_metadata_dump.js 包名**  
5、导出的文件在  
/data/data/PackageName/global-metadata.dat  
（所有的data搜索出来的都会保存下来，如果dat后缀有多的，建议最后自行确认下使用哪一个。）  
