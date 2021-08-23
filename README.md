# EasyCraft 官方 BDS 插件注入器

这个通过开服器的方式来实现的BDS的插件注入, 无需任何第三方 exe 或是 chakra.dll

只需让 EasyCraft 加载此开服器, 在开服配置中选中此开服器. 将要加载的 DLL 放置在 服务器目录 /dll 文件夹下.

在开服的时候将会自动遍历此目录下的DLL文件并加载. 

如有问题请提 Issue

代码参考:

Player/nanolauncher

dotnet/runtime

[MSDN Fourm](https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/20e31615-bb77-4e57-a1d3-681d53801190/native-api-createprocess-amp-redirecting-output?forum=windowsgeneraldevelopmentissues)

Licence under GPLv3

DON'T BE EVIL

