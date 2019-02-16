---
title: Git常用命令一览表
date: 2017-09-03 10:30:19
tags: 
    - Git
---

> Git常用命令列表，以备快速查阅使用！

<!-- more -->

## 创建初始化

````bash
## clone an existing repository（克隆一个Git仓库到本地）
git clone http://user@domain.com/repo.git
##Create a new local repository(初始化一个Git本地仓库)
git init
````

## 本地有改动时

````bash
##Changed files in your working directory 除了问题时，先用该命令查看本地状态
git status
##Changes to tracked files 对比加入版本控制的文件
git diff
##Add all current changes to the next commit 将本地的所有变更提交到暂存区
git add .
##Add some changes in <file> to the next commit 同一个文件进行多次变更并且想要记录每次变更的提交时会用到该命令
git add -p <file>
##Commit all local changes in tracked files 提交所有本地加入版本控制的所有变更到本地
git commit -a
##Commit previously staged changes 提交放入暂存区的变更
git commit
##Change the last commit 修改没有推送到远端的commit注释
##Don‘t amend published commits! 已经推送的提交信息永远不能更改了，不要尝试amend了！
git commit --amend
````

## 提交历史相关

````bash
##Show all commits, starting with newest 查看提交历史
git log
##Show changes over time for a specific file 查看某一个文件的提交历史
git log -p <file>
##Who changed what and when in <file> 查看一个文件的提交历史
git blame <file>
````

## 分支及标签相关

````bash
##List all existing branches 查看所有存在的分支（包含远程分支）
git branch -av
##Switch HEAD branch 切换分支（本质就是变更HEAD头指针，顺便更新该项目下的文件为相应分支的状态）
git checkout <branch>
##Create a new branch based on your current HEAD 基于当前分支的状态创建新分支
git branch <new-branch>
##Create a new tracking branch based on a remote branch 拉取新的远程分支到本地
git checkout --track <remote/branch>
##Delete a local branch 删除本地分支（不能删除当前所在的分支）
git branch -d <branch>
##Mark the current commit with a tag 基于当前所在的分支及版本打标签
git tag <tag-name>
````

## 提交本地及推送远程

````bash
##List all currently configured remotes 查看所有远端的列表
git remote -v
##Show information about a remote 查看某一远端的信息
git remote show <remote>
##Add new remote repository, named <remote> 添加一个远端仓库
git remote add <shortname> <url>
##Download all changes from <remote>, but don‘t integrate into HEAD 获取远端的更新记录，但是不改变当前的HEAD指针（即，不对本地文件内容做更新修改）
git fetch <remote>
##Download changes and directly merge/integrate into HEAD 获取远端的更新记录，并应用到本地
git pull <remote> <branch>
##Publish local changes on a remote 向远端推送本地提交（commit）的变更
git push <remote> <branch>
##Delete a branch on the remote 删除远端仓库的一个分支
git branch -dr <remote/branch>
##Publish your tags 推送标签到远端（注：我们的gitblit中没有开放开发人员的推送tag权限）
git push --tags
````

## 合并

````bash
##Merge <branch> into your current HEAD 将指定的分支合并到当前分支上
git merge <branch>
##Rebase your current HEAD onto <branch> 以rebase的方式合并分支
##Don‘t rebase published commits! 注：不要已rebase的方式合并已推送到远程的提交
git rebase <branch>
##Abort a rebase 终止rebase合并
git rebase --abort
##Continue a rebase after resolving conflicts 在rebase合并过程中可能出现冲突，在解决冲突后进行继续rebase方式的合并
git rebase --continue
````

## 重置与回滚

````bash
##Discard all local changes in your working directory 丢弃本地加入到版本控制的所有变更
git reset --hard HEAD
##Discard local changes in a specific file 将丢弃指定文件的本地未提交的变更
git checkout HEAD <file>
##Revert a commit (by producing a new commit with contrary changes) 生成一个新的提交来撤销某次提交，此次提交之前的commit都会被保留
git revert <commit>
##Reset your HEAD pointer to a previous commit 回到某次提交，提交及之前的commit都会被保留，但是此次之后的修改都会被退回到暂存区
##…and discard all changes since then 丢弃本地所有修改的reset模式
git reset --hard <commit>
##…and preserve all changes as unstaged changes 仅用HEAD指向的目录树重置暂存区，工作区不会受到影响
git reset <commit>
##…and preserve uncommitted local changes 仅用HEAD指向的目录树重置暂存区，保留之前工作区未提交的变更
git reset --keep <commit>
````