---
title: Git的分支合并时非同源的几种解决方案分析
date: 2017-09-19 09:15:18
tags:
    - git
categories:
    - 经验积累
---

> 刚毕业入职来到公司，刚好赶上版本控制SVN转Git。于是，趁着这个时机，深入了解一下Git。当然在切换使用过程中也才过许多坑，在此进行一下经验总结，以使后来者少走弯路。

- 首先，介绍一下来到公司时面临的现状。由于公司是做的银行系统，需要较高的保密性，故开发在局域网内进行，应用coding.net等的在线git仓库不可行，需要到客户银行进行现场开发及公司版本的开发，故存在现场和基地两个地方的同时开发。其中，现场主要是针对行方用户测试的缺陷修改以及外围系统（支付系统、手机银行等近60个外围系统）的接入联调等；基地主要是新功能新需求的开发等。因此，需要定期将基地开发的新功能合并到现场并进行现场测试。
- 接下来，在我们的第一次将基地代码合并到现场时，总共有3个项目源码，其中最大的一个项目遇到了如下问题：

````
fatal: refusing to merge unrelated histories
````

也就是说两部分代码是非同源的。经了解最初将基地代码部署到现场时，直接将基地的.git文件夹删除，作为一个新的没有提交历史的项目推送到了现场搭建的Git仓库。从而导致了虽然基地与现场最初的代码一致，但是没有相关的提交历史（即没有基于某一个共同的Git版本号做的后续开发）。使得基于Git的日志的合并无法进行。

#### 针对这个问题，我们进行了如下几种尝试：

##### Git的强制合并
进行两个分支合并时添加 --allow-unrelated-histories 参数，进行强制的diff合并。
经尝试，发现项目有1680个文件删除，5884个文件新增，5117个文件修改。
这就意味着我们要解决5117个文件的冲突。[:sad]

此方案不可行，pass掉。

##### Git的打补丁的方式
通过将基地拿到现场最初版本到本次合并的时间段内的基地的提交通过发布补丁包的方式，再将补丁包应用到现场的代码中。

```` bash
git -c diff.mnemonicprefix=false -c core.quotepath=false -c credential.helper=manager-st format-patch --stdout -1 6531df71a840ab9540b88f6c85cf50c1b70be0db

git -c diff.mnemonicprefix=false -c core.quotepath=false -c credential.helper=manager-st format-patch --stdout -1 90d424d070170dd6e2257f4b1a877e8c164aad62

git -c diff.mnemonicprefix=false -c core.quotepath=false -c credential.helper=manager-st format-patch --stdout -1 feb2a8ac5788a09ad3a838d5db830c779473092b

git -c diff.mnemonicprefix=false -c core.quotepath=false -c credential.helper=manager-st format-patch --stdout -1 e06a38c3c57c902cf9abf89d125027deb6df142b

git -c diff.mnemonicprefix=false -c core.quotepath=false -c credential.helper=manager-st format-patch --stdout -1 c3e764c806bdbd7a41bf66ccdc583d9b6d8ddc08

git -c diff.mnemonicprefix=false -c core.quotepath=false -c credential.helper=manager-st format-patch --stdout -1 c8ff104b5446e1dd6086aa881ee8f4d997fe359b

git -c diff.mnemonicprefix=false -c core.quotepath=false -c credential.helper=manager-st format-patch --stdout -1 50a8bbd0bf178e4c5ca0b59f49a8e91b70b4bc84

...... ......
````

生成完补丁包后，发现补丁包大小为1.67G（感觉要跪），将补丁开始应用到当前项目。
````bash
git -c diff.mnemonicprefix=false -c core.quotepath=false -c credential.helper=manager-st am -p 1 --3way \patch.diff
````
由于补丁包太大，尝试应用补丁不可行（工作量太大，相当于rebase操作总共322步，而且每步都要解决不同量[不可预估]的冲突）！

##### 通过抽取增量的方式

开始尝试进行增量的抽取，将基地拿到现场最初版本到本次合并的时间段内的基地的增量抽取出来。即，只基地两个时间点的代码diff，获取基地这段时间的文件变更列表，现场仅考虑基地有变更的文件。再通过对比工具（如：BeyondCompare）将增量列表中的文件对比合并到现场的代码中。
通过抽取增量后，发现有7个文件删除、2173个文件已添加、274个文件已修改。
这意味着我们要比较解决的冲突文件为274个文件，这比方案一要解决的冲突降低了一个数量级。

> 经权衡后，我们选择了抽取增量的方式进行合并。

其余的2个较小的项目，由于在最初到现场时保留了.git文件夹（也是奇怪，为何不是都保留或都不保留）。可以进行Git自动合并。要解决的冲突量都在30个文件以内，而且冲突文件大多数为公共文件、注册文件等。故工作量时在可接受范围内。

> 经验教训，将源代码部署到一个新的环境进行两地各自局域网内同时开发时，需要合并代码的一定要保留.git文件夹，保留之前的提交记录、版本号等。