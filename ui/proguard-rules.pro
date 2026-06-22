# WireGuard Android ProGuard/R8 rules
# dnsjava 引用了可选的 JNA/Lombok/SLF4J/JNDI 类，运行时不会用到
-dontwarn com.sun.jna.**
-dontwarn javax.naming.**
-dontwarn lombok.**
-dontwarn org.slf4j.impl.**
-dontwarn sun.net.spi.nameservice.**
