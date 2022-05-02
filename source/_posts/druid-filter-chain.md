---
title: druid 源码分析之 filter-chain 机制
date: 2019-04-16 13:46:55
categories: 源码分析
tags:
---

> Druid，一个为监控而生的高性能数据库连接池，最近开始拜读温少的druid代码。接下来我将通过一系列文章记录阅读源码过程中的一些个人见解。本片文章讲述为druid带来强大扩展性的 filter-chain 模式。

Druid的filter-chain模式相关的接口和类包括：Filter、FilterAdapter、FilterEventAdapter、FilterChain、FilterChainImpl、FilterManger以及相关具体的扩展实现 StatFilter、LogFilter 相关类。

Filter的相关类及层级关系如下:

- Filter
  - FilterAdapter
    - FilterEventAdapter
      - StatFilter
      - LoggerFilter
- FilterChain
  - FilterChainImpl
- FilterManager

1、Filter具体功能实例在DataSource初始化时创建一个Filter链List<Filter>，且是无状态或共享状态的。供由该DataSource派生的Connection、Statement、PreparedStatement等功能类共用；

2、每一个功能类的实例都至少持有一个FilterChainImpl实例，FilterChainImpl相当于一个visitor遍历List<Filter>。相当于一个Filter的连接器；

3、FilterManager为Filter相关实现类加载器，通过配置文件初始化Filter；

4、filters与autoFilters。

相关类的具体职责如下：
Filter接口：定义了过滤器需要关注的事件，以及可以处理的事件；
FilterChain接口：定义过滤器关注的事件，与Filter职责类似；并串联Filter实例，并执行最终方法；
FilterChainImpl类：FilterChian接口的具体实现；
FilterAdapter抽象类：定义了基本的Filter接口默认实现；
FilterEventAdapter抽象类：在FilterAdapter类的基础上，对关注的事件分为doBefore、do、doAfter相关操作；
FilterManger类：使Filter具体实现可通过SPI方式加载；

StatFilter、Slf4jLogFilter类：实现了doBefore,doAfter,这样的话，配置了这两个filter的类就可以做一些切面的事情了。

下面通过Slf4jLogFilter类的加载及

每个执行包装类实例中都包含一个FilterChainImpl实例，通过createChain()创建，通过recycleFilterChain(chain)进行回收再用。

调用 setFilter() 时，Filter的加载过程：

1. 判断字符串是否以 ! 开头，如以 ! 开头，则清空之前加载的Filter链，再加载新的Filter实例；
2. 通过 FilterManager.loadFilter(List<Filter>, String) 加载Filter实例到Filter链中；
  2.1 FilterManager 类的静态代码块通过 SPI 方式先后通过 SystemClassLoader、FilterManager.class.getClassLoader、ThreadContextClassLoader、FilterManager.class.getClassLoader 加载4次 META-INF/druid-filter.properties 获取Filter别名与类路径的Map映射；
  2.2 根据用户的 setFilter() 实例化对应的Filter实例并加到List<Filter>中。

````
<property name="validationQuery" value="SELECT 'x'" />
<property name="testWhileIdle" value="true" />
<property name="testOnBorrow" value="false" />
<property name="testOnReturn" value="false" />
````