u3d游戏global-metadata.dat加密，根据global-metadata.dat头部特征，从内存中抠取。

# 使用方法
1、启动手机的 frida 服务。  
2、在js文件的存放目录下，右键，打开PowerShell。  
3、执行以下代码：  
**frida -U -l global-metadata_dump.js 包名**  
