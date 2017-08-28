---
title: Bro脚本编写
date: 2016-11-22 14:41:14
tags: 
    - 网络安全
categories: 
    - 网络安全
---

- 本文英文原版链接为：https://www.bro.org/sphinx/scripting/index.html#understanding-bro-scripts ，仅供参考。

## Understanding Bro Scripts
Bro 包括事件驱动的脚本语言，为组织扩展和自定义Bro的功能提供了主要方法。事实上，Bro生成的所有输出事实上都是由Bro脚本生成的。将Bro作为幕后处理和生成事件的实体几乎更容易，而Bro脚本语言是我们使用者可以实现通信的媒介。Bro脚本有效地通知Bro，如果有一个类型的事件，我们定义，然后让我们有关于连接的信息，所以我们可以执行一些功能。例如，ssl.log文件由Bro脚本生成，该脚本遍历整个证书链，并在证书链中的任何步骤无效时发出通知。整个过程是通过告诉Bro，如果它看到一个服务器或客户端问题SSL HELLO消息，我们想知道有关该连接的信息。

通过查看完整的脚本将其分解为可识别的组件来了解Bro的脚本语言通常是最容易的。在这个例子中，我们将看到Bro如何检查从网络流量提取的各种文件的SHA1哈希与Team Cymru Malware哈希注册表。 Cymru Malware Hash注册表的一部分包括使用格式 .malware.hash.cymru.com在域上执行主机查找的功能，其中是文件的SHA1哈希。团队Cymru也填充他们的DNS响应的TXT记录与“首见”时间戳和数字“检测率”。要了解的重要方面是Bro已经通过Files框架生成文件的哈希，但它是脚本detect-MHR.bro，负责生成适当的DNS查找，解析响应，并生成是否适用的通知。
````
detect-MHR.bro

##! Detect file downloads that have hash values matching files in Team
##! Cymru's Malware Hash Registry (http://www.team-cymru.org/Services/MHR/).

@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

module TeamCymruMalwareHashRegistry;

export {
    redef enum Notice::Type += {
        ## The hash value of a file transferred over HTTP matched in the
        ## malware hash registry.
        Match
    };

    ## File types to attempt matching against the Malware Hash Registry.
    const match_file_types = /application\/x-dosexec/ |
                             /application\/vnd.ms-cab-compressed/ |
                             /application\/pdf/ |
                             /application\/x-shockwave-flash/ |
                             /application\/x-java-applet/ |
                             /application\/jar/ |
                             /video\/mp4/ &redef;

    ## The Match notice has a sub message with a URL where you can get more
    ## information about the file. The %s will be replaced with the SHA-1
    ## hash of the file.
    const match_sub_url = "https://www.virustotal.com/en/search/?query=%s" &redef;

    ## The malware hash registry runs each malware sample through several
    ## A/V engines.  Team Cymru returns a percentage to indicate how
    ## many A/V engines flagged the sample as malicious. This threshold
    ## allows you to require a minimum detection rate.
    const notice_threshold = 10 &redef;
}

function do_mhr_lookup(hash: string, fi: Notice::FileInfo)
    {
    local hash_domain = fmt("%s.malware.hash.cymru.com", hash);

    when ( local MHR_result = lookup_hostname_txt(hash_domain) )
        {
        # Data is returned as "<dateFirstDetected> <detectionRate>"
        local MHR_answer = split_string1(MHR_result, / /);

        if ( |MHR_answer| == 2 )
            {
            local mhr_detect_rate = to_count(MHR_answer[1]);

            if ( mhr_detect_rate >= notice_threshold )
                {
                local mhr_first_detected = double_to_time(to_double(MHR_answer[0]));
                local readable_first_detected = strftime("%Y-%m-%d %H:%M:%S", mhr_first_detected);
                local message = fmt("Malware Hash Registry Detection rate: %d%%  Last seen: %s", mhr_detect_rate, readable_first_detected);
                local virustotal_url = fmt(match_sub_url, hash);
                # We don't have the full fa_file record here in order to
                # avoid the "when" statement cloning it (expensive!).
                local n: Notice::Info = Notice::Info($note=Match, $msg=message, $sub=virustotal_url);
                Notice::populate_file_info2(fi, n);
                NOTICE(n);
                }
            }
        }
    }

event file_hash(f: fa_file, kind: string, hash: string)
    {
    if ( kind == "sha1" && f?$info && f$info?$mime_type && 
         match_file_types in f$info$mime_type )
        do_mhr_lookup(hash, Notice::create_file_info(f));
    }
````

看起来，Bro脚本有三个不同的部分。首先，有一个没有缩进的基本层，其中库通过 @load 包含在脚本中，命名空间用模块定义。这之后是一个缩进和格式化的部分，作为解释脚本命名空间一部分提供（导出）的自定义变量。最后，有一个第二个缩进和格式化部分，描述了对特定事件（event file_hash）采取的指令。如果你不理解脚本的每一部分，不要慌;我们将在后面的章节中介绍脚本的基础知识。
````
detect-MHR.bro

@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files
````

脚本的第一部分由@load指令组成，其处理在加载的相应目录中的 __load__.bro 脚本。在编写Bro脚本时，@load指令通常被认为是良好的做法，甚至是唯一的推荐方式，以确保它们可以自己使用。虽然在Bro的完全生产部署中这些额外的资源可能不会被加载，但是当你有了一定的Bro脚本编写经验时，可以尝试进行相应加载的优化。当你还是个新手，这个级别的粒度可能先不要尝试了。 @load指令用于确保 Files framework, Notice framework 和用于哈希所有文件的脚本 已由Bro加载。

````
detect-MHR.bro

export {
    redef enum Notice::Type += {
        ## The hash value of a file transferred over HTTP matched in the
        ## malware hash registry.
        Match
    };

    ## File types to attempt matching against the Malware Hash Registry.
    const match_file_types = /application\/x-dosexec/ |
                             /application\/vnd.ms-cab-compressed/ |
                             /application\/pdf/ |
                             /application\/x-shockwave-flash/ |
                             /application\/x-java-applet/ |
                             /application\/jar/ |
                             /video\/mp4/ &redef;

    ## The Match notice has a sub message with a URL where you can get more
    ## information about the file. The %s will be replaced with the SHA-1
    ## hash of the file.
    const match_sub_url = "https://www.virustotal.com/en/search/?query=%s" &redef;

    ## The malware hash registry runs each malware sample through several
    ## A/V engines.  Team Cymru returns a percentage to indicate how
    ## many A/V engines flagged the sample as malicious. This threshold
    ## allows you to require a minimum detection rate.
    const notice_threshold = 10 &redef;
}
````

export部分重新定义了一个枚举常量，它描述了我们将使用Notice框架生成的通知类型。 Bro允许重新定义常量，这可能看起来反直觉。我们将在后面的章节中更深入地介绍常量，而当下，将它们看作只能在Bro开始运行之前更改的变量。所列出的通知类型允许使用NOTICE函数生成TeamCymruMalwareHashRegistry :: Match类型的通知，如下一节所述。通知允许Bro在其默认日志类型之外生成某种额外的通知。通常，此额外通知以电子邮件的形式生成并发送到预配置的地址，但可根据部署的需要进行更改。export部分完成了几个常数的定义，列出了我们要匹配的文件的类型和我们感兴趣的检测阈值的最小百分比。

直到现在，脚本只做了一些简单的设置。在下一节中，脚本开始定义接收给定事件的指令。
````
detect-MHR.bro

function do_mhr_lookup(hash: string, fi: Notice::FileInfo)
    {
    local hash_domain = fmt("%s.malware.hash.cymru.com", hash);

    when ( local MHR_result = lookup_hostname_txt(hash_domain) )
        {
        # Data is returned as "<dateFirstDetected> <detectionRate>"
        local MHR_answer = split_string1(MHR_result, / /);

        if ( |MHR_answer| == 2 )
            {
            local mhr_detect_rate = to_count(MHR_answer[1]);

            if ( mhr_detect_rate >= notice_threshold )
                {
                local mhr_first_detected = double_to_time(to_double(MHR_answer[0]));
                local readable_first_detected = strftime("%Y-%m-%d %H:%M:%S", mhr_first_detected);
                local message = fmt("Malware Hash Registry Detection rate: %d%%  Last seen: %s", mhr_detect_rate, readable_first_detected);
                local virustotal_url = fmt(match_sub_url, hash);
                # We don't have the full fa_file record here in order to
                # avoid the "when" statement cloning it (expensive!).
                local n: Notice::Info = Notice::Info($note=Match, $msg=message, $sub=virustotal_url);
                Notice::populate_file_info2(fi, n);
                NOTICE(n);
                }
            }
        }
    }

event file_hash(f: fa_file, kind: string, hash: string)
    {
    if ( kind == "sha1" && f?$info && f$info?$mime_type && 
         match_file_types in f$info$mime_type )
        do_mhr_lookup(hash, Notice::create_file_info(f));
    }
````

脚本的工作负载包含在file_hash的事件处理程序中。 file_hash事件允许脚本访问与Bro的文件分析框架生成了散列的文件相关联的信息。事件处理程序将文件本身作为f传递，将摘要算法的类型用作分类，并将散列生成为散列。
在file_hash事件处理程序中，有一个if语句用于检查正确类型的散列，在这种情况下是一个SHA1散列。它还检查我们定义为感兴趣的MIME类型，如常量match_file_types中定义的。对比表达式f $ info $ mime_type，它使用$ dereference运算符来检查变量f $ info中的值mime_type。如果整个表达式的值为true，那么将调用一个辅助函数来完成其余的工作。在该函数中，局部变量被定义为保存由与.malware.hash.cymru.com连接的SHA1哈希组成的字符串;此值将是在恶意软件散列注册表中查询的域。
脚本的其余部分包含在when块中。简而言之，当Bro需要执行异步操作（例如DNS查找）时，使用when块，以确保不会影响性能。 when块执行DNS TXT查找，并将结果存储在本地变量MHR_result中。实际上，继续处理该事件，并且在接收由lookup_hostname_txt返回的值时，执行when块。 when 块将返回的字符串拆分为第一次检测到恶意软件的日期的一部分，并通过分割文本空间并存储本地表变量中返回的值来检测检测率。在do_mhr_lookup函数中，如果split1返回的表有两个条目，表示成功拆分，我们使用适当的转换函数将检测日期存储在mhr_first_detected中，并将速率存储在mhr_detect_rate中。从这一点上，Bro知道它已经看到一个文件传输，其中有一个已经被团队Cymru Malware哈希注册表看到的散列，脚本的其余部分致力于产生通知。
检测时间被处理为字符串表示并存储在readable_first_detected中。然后，脚本将检测率与之前定义的notice_threshold进行比较。如果检测率足够高，脚本将创建简明的通知描述并将其存储在消息变量中。它还创建了一个可能的URL，以检查样本与virustotal.com的数据库，并调用NOTICE将相关信息移交给Notice framework。
在大约几十行代码中，Bro提供了一个难以实现和部署与其他产品的惊人的实用程序。事实上，Bro声明在这么少的行中做这是一个误导;在Bro中，幕后有真正大量的事情，但它是让分析师已简洁明确的方式访问这些基础层的一种脚本语言。

## The Event Queue and Event Handlers (事件队列和事件处理程序)

Bro的脚本语言是事件驱动的，这是一种来自大多数脚本语言的齿轮变化（组件化？），大多数用户可凭借之前的脚本经验。 Bro中的脚本关键在于处理Bro生成的事件，因为它处理网络流量，通过这些事件更改数据结构的状态，以及根据提供的信息做出决策。这种脚本编写方法通常会对从程序或功能语言转到Bro的用户造成混乱，但是一旦初始冲击造成的困惑消失，每次曝光变得更加清楚。
Bro的核心行为是将事件放置到有序的“事件队列”中，从而允许事件处理程序以先到先服务的方式处理它们。实际上，这是Bro的核心功能，因为没有编写脚本来对事件执行离散操作，将几乎没有可用输出。因此，对事件队列，生成的事件以及事件处理程序处理这些事件的方式的基本理解不仅是学习编写Bro的脚本，而且是理解Bro本身的基础。
熟悉Bro生成的特定事件是构建使用Bro脚本的体系的一大步。 Bro生成的大多数事件在内置函数文件或.bif文件中定义，它们也是联机事件文档的基础。这些内嵌注释使用Broxygen编译为在线文档系统。无论从头开始一个脚本还是阅读和维护别人的脚本，内置的事件定义都是可用的，是一个很好的资源。对于2.0版本，Bro开发人员花费大量精力来组织和记录每个事件。这种努力导致组织的内置函数文件，而且每个条目包含描述性事件名称，传递给事件的参数，以及对函数使用的简明解释。

````
Bro_DNS.events.bif.bro

## Generated for DNS requests. For requests with multiple queries, this event
## is raised once for each.
##
## See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
## information about the DNS protocol. Bro analyzes both UDP and TCP DNS
## sessions.
##
## c: The connection, which may be UDP or TCP depending on the type of the
##    transport-layer session being analyzed.
##
## msg: The parsed DNS message header.
##
## query: The queried name.
##
## qtype: The queried resource record type.
##
## qclass: The queried resource record class.
##
## .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
##    dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
##    dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
##    dns_full_request dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
##    dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
##    dns_rejected non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
##    dns_skip_all_addl dns_skip_all_auth dns_skip_auth
global dns_request: event(c: connection , msg: dns_msg , query: string , qtype: count , qclass: count );
````

上面是事件dns_request的文档的一部分（前面的链接指向生成的文档）。它的组织使得文档，注释和参数列表在Bro使用的实际事件定义之前。 当 Bro检测到发起方发出的DNS请求时，它会发出此事件，因此任何数量的脚本都可以访问Bro数据及事件。在此示例中，Bro不仅传递DNS请求的消息，查询，查询类型和查询类，还传递用于连接本身的记录。

## The Connection Record Data Type (连接记录数据类型)

在Bro定义的所有事件中，绝大多数事件都被传递连接记录数据类型，实际上，使其成为许多脚本解决方案的主干。连接记录本身，正如我们稍后会看到的，是大量的嵌套数据类型，用于通过其生命周期跟踪连接上的状态。让我们通过选择一个适当的事件，生成一些输出到标准输出和剖析连接记录的过程，以获得它的概述。稍后我们将更详细地介绍数据类型。
尽管Bro能够进行分组级处理，但其优势在于始发者和响应者之间的连接的上下文。因此，为连接生命周期的主要部分定义了事件，你将从下面的小型连接相关事件中看到。
````
event.bif.bro

## Generated for every new connection. This event is raised with the first
## packet of a previously unknown connection. Bro uses a flow-based definition
## of "connection" here that includes not only TCP sessions but also UDP and
## ICMP flows.
global new_connection: event(c: connection );
## Generated when a TCP connection timed out. This event is raised when
## no activity was seen for an interval of at least
## :bro:id:`tcp_connection_linger`, and either one endpoint has already
## closed the connection or one side never became active.
global connection_timeout: event(c: connection );
## Generated when a connection's internal state is about to be removed from
## memory. Bro generates this event reliably once for every connection when it
## is about to delete the internal state. As such, the event is well-suited for
## script-level cleanup that needs to be performed for every connection.  This
## event is generated not only for TCP sessions but also for UDP and ICMP
## flows.
global connection_state_remove: event(c: connection );
````
在列出的事件中，将使我们最好地了解连接记录数据类型的事件将是connection_state_remove。正如官方在线文档所述，Bro在决定从内存中删除此事件之前生成此事件，从而有效地忘记了该事件。让我们来看看一个简单的示例脚本，它将输出单个连接的连接记录。
````
connection_record_01.bro

@load base/protocols/conn

event connection_state_remove(c: connection)
    {
    print c;
    }
````
再次，我们从@load开始，这次导入Package：base / protocols / conn脚本，它提供对一般信息和连接状态的跟踪和记录。我们处理connection_state_remove事件，只是打印传递给它的参数的内容。对于这个例子，我们将以“裸模式”运行Bro，它只加载最少数量的脚本以保持可操作性，并且不必为正在运行的脚本加载所需的脚本。虽然裸模式是并入Bro的低级功能，在这种情况下，我们将使用它来演示Bro的不同功能如何添加更多的关于连接的信息层。这将让我们有机会看到连接记录的内容，而不会过度填充。
````
# bro -b -r http/get.trace connection_record_01.bro
[id=[orig_h=141.142.228.5, orig_p=59856/tcp, resp_h=192.150.187.43, resp_p=80/tcp], orig=[size=136, state=5, num_pkts=7, num_bytes_ip=512, flow_label=0, l2_addr=c8:bc:c8:96:d2:a0], resp=[size=5007, state=5, num_pkts=7, num_bytes_ip=5379, flow_label=0, l2_addr=00:10:db:88:d2:ef], start_time=1362692526.869344, duration=0.211484, service={

}, history=ShADadFf, uid=CHhAvVGS1DHFjwGM9, tunnel=<uninitialized>, vlan=<uninitialized>, inner_vlan=<uninitialized>, conn=[ts=1362692526.869344, uid=CHhAvVGS1DHFjwGM9, id=[orig_h=141.142.228.5, orig_p=59856/tcp, resp_h=192.150.187.43, resp_p=80/tcp], proto=tcp, service=<uninitialized>, duration=0.211484, orig_bytes=136, resp_bytes=5007, conn_state=SF, local_orig=<uninitialized>, local_resp=<uninitialized>, missed_bytes=0, history=ShADadFf, orig_pkts=7, orig_ip_bytes=512, resp_pkts=7, resp_ip_bytes=5379, tunnel_parents={

}], extract_orig=F, extract_resp=F, thresholds=<uninitialized>]
````
从输出中可以看出，连接记录在打印时是混乱的。定期查看填充的连接记录有助于了解其字段之间的关系，并有助于构建一个用于访问脚本中数据的参考框架。
Bro大量使用嵌套数据结构来存储从连接分析中收集的状态和信息作为完整单元。要分解这个信息集合，你必须使用Bro的字段分隔符$。例如，发起主机由 c$id$orig_h 引用，如果给出叙述涉及 orig_h，其是 id 的成员，其是被称为c的被传递到事件处理程序中的数据结构的成员。鉴于响应程序端口 c$id$resp_p 是 80/tcp，很可能Bro的基本HTTP脚本可以进一步填充连接记录。让我们加载 base/protocols/http 脚本并检查我们的脚本的输出。
Bro使用美元符号作为其字段分隔符，并且在连接记录的输出和脚本中取消引用的变量的正确格式之间存在直接关联。在上面脚本的输出中，在括号之间收集信息组，这些信息对应于Bro脚本中的 $-delimiter。
````
connection_record_02.bro

@load base/protocols/conn
@load base/protocols/http

event connection_state_remove(c: connection)
    {
    print c;
    }
````
bro脚本:
````
# bro -b -r http/get.trace connection_record_02.bro
[id=[orig_h=141.142.228.5, orig_p=59856/tcp, resp_h=192.150.187.43, resp_p=80/tcp], orig=[size=136, state=5, num_pkts=7, num_bytes_ip=512, flow_label=0, l2_addr=c8:bc:c8:96:d2:a0], resp=[size=5007, state=5, num_pkts=7, num_bytes_ip=5379, flow_label=0, l2_addr=00:10:db:88:d2:ef], start_time=1362692526.869344, duration=0.211484, service={

}, history=ShADadFf, uid=CHhAvVGS1DHFjwGM9, tunnel=<uninitialized>, vlan=<uninitialized>, inner_vlan=<uninitialized>, conn=[ts=1362692526.869344, uid=CHhAvVGS1DHFjwGM9, id=[orig_h=141.142.228.5, orig_p=59856/tcp, resp_h=192.150.187.43, resp_p=80/tcp], proto=tcp, service=<uninitialized>, duration=0.211484, orig_bytes=136, resp_bytes=5007, conn_state=SF, local_orig=<uninitialized>, local_resp=<uninitialized>, missed_bytes=0, history=ShADadFf, orig_pkts=7, orig_ip_bytes=512, resp_pkts=7, resp_ip_bytes=5379, tunnel_parents={

}], extract_orig=F, extract_resp=F, thresholds=<uninitialized>, http=[ts=1362692526.939527, uid=CHhAvVGS1DHFjwGM9, id=[orig_h=141.142.228.5, orig_p=59856/tcp, resp_h=192.150.187.43, resp_p=80/tcp], trans_depth=1, method=GET, host=bro.org, uri=/download/CHANGES.bro-aux.txt, referrer=<uninitialized>, version=1.1, user_agent=Wget/1.14 (darwin12.2.0), request_body_len=0, response_body_len=4705, status_code=200, status_msg=OK, info_code=<uninitialized>, info_msg=<uninitialized>, tags={

}, username=<uninitialized>, password=<uninitialized>, capture_password=F, proxied=<uninitialized>, range_request=F, orig_fuids=<uninitialized>, orig_filenames=<uninitialized>, orig_mime_types=<uninitialized>, resp_fuids=[FakNcS1Jfe01uljb3], resp_filenames=<uninitialized>, resp_mime_types=[text/plain], current_entity=<uninitialized>, orig_mime_depth=1, resp_mime_depth=1], http_state=[pending={

}, current_request=1, current_response=1, trans_depth=1]]
````
添加 base/protocols/http 脚本将填充连接记录的 http = [ ] 成员。虽然Bro在后台做了大量的工作，但它是通常所谓的细化的实时决断的“脚本”。如果我们继续以“裸模式”运行，我们可以通过@load语句缓慢地添加基础结构。例如，是否为 @load base/frameworks/logging，Bro将在当前工作目录中为我们生成 conn.log 和 http.log。如上所述，包括适当的@load语句不仅是良好的实践，而且还可以帮助指示在脚本中使用哪些功能。花一秒钟运行不带-b标志的脚本，并在将所有Bro的功能应用于跟踪文件时检查输出。

## Data Types and Data Structures (数据类型和数据结构)

### Scope （作用域）

在开始探索Bro的本地数据类型和数据结构之前，了解Bro中可用的不同级别的可用范围以及在脚本中使用它们的适当时间非常重要。 Bro中变量的声明有两种形式。变量可以使用或不使用SCOPE名称中的定义来声明：TYPE或SCOPE name = EXPRESSION;如果EXPRESSION评估为与TYPE相同的类型，则每个都会产生相同的结果。关于使用哪种类型的声明的可由个人偏好和可读性决定。
````
data_type_declaration.bro

event bro_init()
    {
    local a: int;
    a = 10;
    local b = 10;

    if ( a == b )
    print fmt("A: %d, B: %d", a, b);
    }
````
#### Global Variables （全局变量）

当需要跟踪变量的状态时，使用全局变量，这并不令人惊讶。虽然有一些注意事项，当脚本使用全局范围声明变量时，该脚本正在授予从其他脚本访问该变量的权限。但是，当脚本使用module关键字为脚本提供命名空间时，必须更多地注意全局变量的声明，以确保预期的结果。当在具有命名空间的脚本中声明全局时，有两种可能的情况。情景一，变量只在命名空间的上下文中可用。在这种情况下，同一命名空间中的其他脚本将有权访问声明的变量，而使用不同命名空间或没有命名空间的脚本将无法访问该变量；情景二，如果在 export { … } 块中声明了一个全局变量，该变量通过命名约定 MODULE :: variable_name 可用于任何其他脚本。
下面的声明来自 policy/protocols/conn/known-hosts.bro 脚本，并声明一个名为known_hosts的变量作为已知命名空间内的唯一IP地址的全局集合，并将其导出以在Known命名空间外部使用。如果我们要使用known_hosts变量，我们可以通过Known :: known_hosts来访问它。
````
known-hosts.bro

module Known;

export {
    global known_hosts: set[addr] &create_expire=1day &synchronized &redef;
}
````
上面的示例还使用 export { … } 块。当在脚本中使用module关键字时，声明的变量被称为在该模块的 “namespace”。其中作为一个全局变量，当它没有在一个模块中声明时，它的名称可以被访问，一个模块中声明的全局变量必须被导出，然后通过MODULE_NAME :: VARIABLE_NAME访问。如上面的例子，我们将能够通过Known :: known_hosts在一个单独的脚本变量中访问known_hosts，因为known_hosts在Known命名空间下的导出块中被声明为一个全局变量。

#### Constants （常量）

Bro也使用常量，由const关键字表示。与全局变量不同，常量只能在解析时使用＆redef属性设置或更改。之后（在运行时）常量是不可更改的。在大多数情况下，可重定义的常量在Bro脚本中用作配置选项的容器。例如，记录从HTTP流解密的密码的配置选项存储在 HTTP :: default_capture_password 中，如下面从 base/protocols/http/main.bro 中摘录的摘录所示。
````
http_main.bro

module HTTP;

export {
    ## This setting changes if passwords used in Basic-Auth are captured or not.
    const default_capture_password = F &redef;
}
````
因为常量是用＆redef属性声明的，如果我们需要在全局上打开这个选项，我们可以通过在我们的 site/local.bro 文件中添加下面一行来启动Bro。
````
data_type_const_simple.bro

@load base/protocols/http

redef HTTP::default_capture_password = T;
````
虽然可重定义的常量的想法可能是奇怪的，但常量只能在解析时改变的约束仍然保留即使使用＆redef属性。在下面的代码片段中，通过端口索引的字符串表被声明为常量，然后通过redef语句将两个值添加到表中。然后在bro_init事件中打印该表。如果我们尝试改变事件处理程序中的表，则Bro将告知用户错误，并且脚本将失败。
````
data_type_const.bro

const port_list: table[port] of string &redef;

redef port_list += { [6666/tcp] = "IRC"};
redef port_list += { [80/tcp] = "WWW" };

event bro_init()
    {
    print port_list;
    }
````
执行bro脚本：
````
# bro -b data_type_const.bro
{
[80/tcp] = WWW,
[6666/tcp] = IRC
}
````
#### Local Variables （局部变量）

尽管全局变量和常量通过各种手段在脚本中广泛可用，但当变量使用局部作用域定义时，它的可用性仅限于它所声明的事件或函数的主体。局部变量倾向于用于仅在特定范围内需要的值，并且一旦脚本的处理超出该范围并且不再使用，则该变量被删除。 Bro维护本地化的名称与全局可见的名称分开，下面将举例说明。
````
data_type_local.bro

function add_two(i: count): count
    {
    local added_two = i+2;
    print fmt("i + 2 = %d", added_two);
    return added_two;
    }

event bro_init()
    {
    local test = add_two(10);
    }
````
脚本执行事件处理程序bro_init，它反过来调用参数为10的函数add_two（i：count）。一旦Bro进入add_two函数，它将提供一个局部范围的变量 added_two 来保存 i + 2 . add_two 函数然后打印added_two 变量的值，并将其值返回到 bro_init 事件处理程序。此时，变量added_two已经超出范围，并且不再存在，而值12仍在使用并存储在本地作用域变量测试中。当Bro完成处理bro_init函数时，名为test的变量不再在作用域中，因为没有对值12的其他引用，该值也被删除。

### Data Structures

在没有覆盖Bro中可用的数据结构的情况下，很难以实用的方式讨论Bro的数据类型。当在数据结构内部使用时，揭示了数据类型的一些更有趣的特性，但是考虑到数据结构由数据类型组成，它相当快地转化为“鸡和蛋”问题。因此，我们将从鸟瞰图引入数据类型，然后再进入数据结构，并从中更全面地探索数据类型。
下表显示了Bro中使用的原子类型，如果你有一些脚本编写经验，前四个应该看起来很熟悉，而剩下的六个在其他语言中不太常见。网络安全监控平台的脚本语言具有相当强大的以网络为中心的数据类型，并且在这里记录这些数据类型可能会为您节省一个重新发明轮子的时间。
````
Data Type	Description
int	64 bit signed integer
count	64 bit unsigned integer
double	double precision floating precision
bool	boolean(T/F)
addr	IP address, IPv4 and IPv6
port	transport layer port
subnet	CIDR subnet mask
time	absolute epoch time
interval	a time interval
pattern	regular expression
````
#### Sets
Bro中的 sets 用于存储相同数据类型的唯一元素。实质上，你可以将它们视为“一组唯一的整数”或“一组唯一的IP地址”。虽然集合的声明可能因收集的数据类型而异，但集合将始终包含唯一元素，集合中的元素将始终具有相同的数据类型。这样的要求使得集合数据类型对于已经自然唯一的信息（例如端口或IP地址）是完美的。下面的代码片段显示了局部范围集合的显式和隐式声明。
````
data_struct_set_declaration.bro

event bro_init()
    {
    local ssl_ports: set[port];
    local non_ssl_ports = set( 23/tcp, 80/tcp, 143/tcp, 25/tcp );
    }
````
如你所见，使用格式SCOPE var_name：set [TYPE]声明集合。使用add和delete语句实现在集合中添加和删除元素。一旦你有元素插入到集合中，你可能需要迭代该集合或测试集合中的成员资格，这两个都由 in 运算符覆盖。在迭代一个集合的情况下，结合使用 for 语句和 in 运算符将允许你顺序处理集合的每个元素，如下所示。
````
data_struct_set_declaration.bro

for ( i in ssl_ports )
        print fmt("SSL Port: %s", i);

for ( i in non_ssl_ports )
        print fmt("Non-SSL Port: %s", i);
````
这里，for语句循环存储临时变量i中的每个元素的集合的内容。对于for循环的每次迭代，选择下一个元素。由于集合不是有序数据类型，因此不能保证元素作为for循环过程的顺序。
要测试集合中的成员资格，in语句可以与if语句组合，以返回true或false值。如果条件中的确切元素已经在集合中，则条件返回true，并且正文执行。 in语句也可以被否定！运算符创建条件的逆。虽然我们可以重写相应的行，如同（！（587 / tcp in ssl_ports））尽量避免使用这个结构;相反，取消in运算符本身。虽然功能是相同的，使用！in是更有效的，以及一个更自然的结构，这将有助于您的脚本的可读性。
````
data_struct_set_declaration.bro

# Check for SMTPS 
if ( 587/tcp !in ssl_ports )
    add ssl_ports[587/tcp];
````
您可以在下面看到完整的脚本及其输出。
````
data_struct_set_declaration.bro

event bro_init()
    {
    local ssl_ports: set[port];
    local non_ssl_ports = set( 23/tcp, 80/tcp, 143/tcp, 25/tcp );

    # SSH
    add ssl_ports[22/tcp];
    # HTTPS
    add ssl_ports[443/tcp];
    # IMAPS
    add ssl_ports[993/tcp];

    # Check for SMTPS 
    if ( 587/tcp !in ssl_ports )
    add ssl_ports[587/tcp];

    for ( i in ssl_ports )
    print fmt("SSL Port: %s", i);

    for ( i in non_ssl_ports )
    print fmt("Non-SSL Port: %s", i);
    }
````
执行data_struct_set_declaration.bro脚本：
````
# bro data_struct_set_declaration.bro
SSL Port: 22/tcp
SSL Port: 443/tcp
SSL Port: 587/tcp
SSL Port: 993/tcp
Non-SSL Port: 80/tcp
Non-SSL Port: 25/tcp
Non-SSL Port: 143/tcp
Non-SSL Port: 23/tcp
````
#### Tables
Bro中的表是键到值或yield的映射。虽然值不必是唯一的，但表中的每个键必须是唯一的，以保留键与值的一对一映射。
````
data_struct_table_declaration.bro

event bro_init()
    {
    # Declaration of the table.
    local ssl_services: table[string] of port;

    # Initialize the table.
    ssl_services = table(["SSH"] = 22/tcp, ["HTTPS"] = 443/tcp);

    # Insert one key-yield pair into the table.
    ssl_services["IMAPS"] = 993/tcp;

    # Check if the key "SMTPS" is not in the table.
    if ( "SMTPS" !in ssl_services )
    ssl_services["SMTPS"] = 587/tcp;

    # Iterate over each key in the table.
    for ( k in ssl_services )
    print fmt("Service Name:  %s - Common Port: %s", k, ssl_services[k]);
    }
````
执行data_struct_table_declaration.bro脚本：
````
# bro data_struct_table_declaration.bro
Service Name:  SSH - Common Port: 22/tcp
Service Name:  HTTPS - Common Port: 443/tcp
Service Name:  SMTPS - Common Port: 587/tcp
Service Name:  IMAPS - Common Port: 993/tcp
````
在本例中，我们编译了一个启用SSL的服务及其公共端口的表。表的显式声明和构造函数在两个不同的行上，并且布置keys（strings）的数据类型和yields（port）的数据类型，然后填充一些示例键值对。您还可以使用表访问器将一个键值对插入表中。当在表上使用 in 运算符时，你有效地使用表的键。在if语句的情况下，in运算符将检查键集合中的成员资格，并返回true或false值。该示例显示如何检查SMTPS是否不在ssl_services表的键集合中，如果条件成立，我们将键值对添加到表中。最后，该示例显示如何使用for语句来迭代表中当前的每个键。
除了简单的例子，表可能变得非常复杂，因为表的键和值变得更复杂。表可以具有由多种数据类型组成的键，甚至包括一系列称为“元组”的元素。在Bro中使用复杂表格所获得的灵活性意味着编写脚本的人的高复杂性成本，但是由于Bro作为网络安全平台的强大性，有效性得到了提高。
````
data_struct_table_complex.bro

event bro_init()
    {
    local samurai_flicks: table[string, string, count, string] of string;

    samurai_flicks["Kihachi Okamoto", "Toho", 1968, "Tatsuya Nakadai"] = "Kiru";
    samurai_flicks["Hideo Gosha", "Fuji", 1969, "Tatsuya Nakadai"] = "Goyokin";
    samurai_flicks["Masaki Kobayashi", "Shochiku Eiga", 1962, "Tatsuya Nakadai" ] = "Harakiri";
    samurai_flicks["Yoji Yamada", "Eisei Gekijo", 2002, "Hiroyuki Sanada" ] = "Tasogare Seibei";

    for ( [d, s, y, a] in samurai_flicks )
    print fmt("%s was released in %d by %s studios, directed by %s and starring %s", samurai_flicks[d, s, y, a], y, s, d, a);
    }
````
执行data_struct_table_complex.bro脚本：
````
# bro -b data_struct_table_complex.bro
Harakiri was released in 1962 by Shochiku Eiga studios, directed by Masaki Kobayashi and starring Tatsuya Nakadai
Goyokin was released in 1969 by Fuji studios, directed by Hideo Gosha and starring Tatsuya Nakadai
Tasogare Seibei was released in 2002 by Eisei Gekijo studios, directed by Yoji Yamada and starring Hiroyuki Sanada
Kiru was released in 1968 by Toho studios, directed by Kihachi Okamoto and starring Tatsuya Nakadai
````
此脚本显示由两个字符串索引的字符串，一个计数和一个最后一个字符串的示例表。使用元组作为聚合键，顺序很重要，因为顺序的改变将导致新的键。在这里，我们使用表来跟踪导演，工作室，年份或发行版和一系列的的主演。重要的是要注意，在for语句的情况下，它是一个全类型或无类型的迭代。我们不能重复，例如，董事;我们必须以确切的格式作为键本身进行迭代。在这种情况下，我们需要围绕四个临时变量的方括号作为我们迭代的集合。虽然这是一个假设的例子，我们可以很容易地有包含IP地址（addr），端口（port）的键，甚至一个字符串作为反向计算主机名查找的结果。

#### Vectors

如果你处于Bro的编程环境下，你可能会或不熟悉矢量数据类型，具体取决于你选择的语言。表面上，向量执行与具有无符号整数作为其索引的关联数组相同的功能。然而，它们比这更有效，并且允许有序访问。因此，任何时候，你需要顺序存储相同类型的数据，在Bro你应该选择vector。vector是对象的集合，所有对象都具有相同的数据类型，元素可以动态添加或删除。由于矢量对其元素使用连续存储，所以可以通过 zero-index 的数值偏移来访问 vector 的内容。
Vector声明的格式遵循其他声明的模式，即SCOPE v：vector of T，其中v是 vector 的名称，T 是其成员的数据类型。例如，以下代码片段显示了两个局部范围 vector 的显式和隐式声明。脚本通过在末尾插入值来填充第一个向量;它通过在两个垂直管道之间放置vector名称来获得vector的当前长度，然后打印两个vector的内容及其当前长度。
````
data_struct_vector_declaration.bro

event bro_init()
    {
    local v1: vector of count;
    local v2 = vector(1, 2, 3, 4);

    v1[|v1|] = 1;
    v1[|v1|] = 2;
    v1[|v1|] = 3;
    v1[|v1|] = 4;

    print fmt("contents of v1: %s", v1);
    print fmt("length of v1: %d", |v1|);
    print fmt("contents of v2: %s", v2);
    print fmt("length of v2: %d", |v2|);
    }
````
执行data_struct_vector_declaration.bro脚本：
````
# bro data_struct_vector_declaration.bro
contents of v1: [1, 2, 3, 4]
length of v1: 4
contents of v2: [1, 2, 3, 4]
length of v2: 4
````
在很多情况下，vector中存储元素仅仅是用于对它们进行迭代。使用for关键字很容易迭代向量。下面的示例迭代一个IP地址的vector，对于每个IP地址，掩码以18位地址。 for关键字用于生成一个局部范围的变量 i，它将保存向量中当前元素的索引。使用i作为addr_vector的索引，我们可以使用addr_vector [i]访问vector中的当前项。
````
data_struct_vector_iter.bro

event bro_init()
    {
    local addr_vector: vector of addr = vector(1.2.3.4, 2.3.4.5, 3.4.5.6);

    for (i in addr_vector)
    print mask_addr(addr_vector[i], 18);
    }
````
执行data_struct_vector_iter.bro脚本：
````
# bro -b data_struct_vector_iter.bro
1.2.0.0/18
2.3.0.0/18
3.4.0.0/18
````
### Data Types Revisited
#### addr

地址或地址数据类型管理覆盖惊人的大量地面，同时保持简洁。 IPv4，IPv6甚至主机名常量都包含在addr数据类型中。虽然IPv4地址使用默认的点分四元格式，但IPv6地址使用RFC 2373定义的符号，加上整数地址的方括号。当你闯进一台主机时，Bro会处于用户的角度做一点手脚；主机名常量实际上是一组地址。 Bro将在它看到正在使用的主机名常量时发出DNS请求，并返回其元素是DNS请求答案的集合。例如，如果您要使用本地google = www.google.com ;你最终会得到一个局部范围的set[addr]，其中的元素代表google的当前循环DNS条目集。初看起来，这看起来微不足道，但Bro的另一个例子，通过以实用的方式应用抽象，使得通用Bro脚本更方便一些。 （请注意，这些IP地址永远不会在Bro处理期间更新，因此通常此机制对于预期保持静态的地址最有用.）

#### port

Bro中的传输层端口号以 <unsigned integer > / < protocol name > 的格式表示，例如22 / tcp或53 / udp。 Bro支持TCP（/ tcp），UDP（/ udp），ICMP（/ icmp）和UNKNOWN（/unknown）作为协议名称。虽然ICMP没有实际端口，Bro通过使用ICMP消息类型和ICMP消息代码分别作为源和目的端口支持ICMP“端口”的概念。端口可以​​使用 == 或 != 运算符进行相等比较，甚至可以进行比较以进行排序。 Bro给予协议名称以下“order”：unknown<tcp <udp <icmp。例如65535 / tcp小于0 / udp。

#### subnet

Bro对CIDR表示法子网具有完全支持作为基本数据类型。当您可以在脚本中以CIDR表示法提供相同的信息时，不需要将IP和子网掩码管理为两个单独的实体。以下示例使用Bro脚本来确定一系列IP地址是否位于使用20位子网掩码的一组子网内。
````
data_type_subnets.bro

event bro_init()
    {
    local subnets = vector(172.16.0.0/20, 172.16.16.0/20, 172.16.32.0/20, 172.16.48.0/20);
    local addresses = vector(172.16.4.56, 172.16.47.254, 172.16.22.45, 172.16.1.1);

    for ( a in addresses )
    {
    for ( s in subnets )
        {
        if ( addresses[a] in subnets[s] )
            print fmt("%s belongs to subnet %s", addresses[a], subnets[s]);
        }
    }

    }
````
因为这是一个不使用任何类型的网络分析的脚本，我们可以处理事件bro_init，它始终由Bro的核心在启动时生成。在示例脚本中，创建两个本地作用域向量以分别保存我们的子网和IP地址列表。然后，使用一组嵌套for循环，我们遍历每个子网和每个IP地址，并使用if语句使用in运算符来比较IP地址和子网。如果IP地址基于最长前缀匹配计算落入给定子网内，则in运算符返回true。例如，10.0.0.0/8中的10.0.0.1将返回true，而192.168.1.0/24中的192.168.2.1将返回false。当我们运行脚本时，我们得到输出列出它所属的IP地址和子网。
````
# bro data_type_subnets.bro
172.16.4.56 belongs to subnet 172.16.0.0/20
172.16.47.254 belongs to subnet 172.16.32.0/20
172.16.22.45 belongs to subnet 172.16.16.0/20
172.16.1.1 belongs to subnet 172.16.0.0/20
````
#### time
虽然当前没有支持的方法在Bro中添加时间常数，但是存在两个内置函数以利用时间数据类型。 network_time和current_time都返回一个时间数据类型，但它们各自根据不同的标准返回一个时间。 current_time函数返回由操作系统定义的所谓挂钟时间。但是，network_time返回从实时数据流或保存的数据包捕获中处理的最后一个数据包的时间戳。这两个函数以时代秒返回时间，这意味着必须使用strftime将输出转换为人类可读的输出。下面的脚本利用connection_established事件处理程序，在每次看到SYN / ACK数据包响应SYN数据包作为TCP握手的一部分时生成文本。生成的文本采用时间戳的格式，并指示发起者和响应者是谁。我们使用％Y％M％d％H：％m：％S的strftime格式字符串产生一个通用的日期时间格式的时间戳。
````
data_type_time.bro

event connection_established(c: connection)
    {
    print fmt("%s:  New connection established from %s to %s\n", strftime("%Y/%M/%d %H:%m:%S", network_time()), c$id$orig_h, c$id$resp_h);
    }
````
当脚本执行时，我们得到一个输出，显示已建立的连接的细节。
````
# bro -r wikipedia.trace data_type_time.bro
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.118\x0a
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.3\x0a
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.3\x0a
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.3\x0a
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.3\x0a
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.3\x0a
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.3\x0a
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.2\x0a
2011/06/18 19:03:09:  New connection established from 141.142.220.235 to 173.192.163.128\x0a
````

#### interval

区间数据类型是Bro中的另一个区域，其中抽象的合理应用是完美的。作为数据类型，间隔表示由数字常数跟随以时间单位表示的相对时间。例如，2.2秒将是2.2秒，三十一天将由31天表示。 Bro支持分别表示微秒，毫秒，秒，分钟，小时和天的usec，msec，sec，min，hr或day。事实上，间隔数据类型允许其定义中出乎意料的变化量。在数字常数之间可以有一个空格，或者它们可以像时间端口一样被挤在一起。时间单位可以是单数或复数。所有这一切加在一起的事实，42小时和42小时是完全有效的，在逻辑上相当于在布罗。然而，要点是增加脚本的可读性和可维护性。间隔甚至可以否定，允许-10分钟表示“十分钟前”。
Bro中的间隔可以对其执行数学运算，允许用户执行加法，减法，乘法，除法和比较运算。此外，当使用 - 运算符比较两个时间值时，Bro返回一个间隔。下面的脚本修改了上一节中启动的脚本，以包括与连接建立报告一起打印的时间增量值。
````
data_type_interval.bro

# Store the time the previous connection was established.
global last_connection_time: time;

# boolean value to indicate whether we have seen a previous connection.
global connection_seen: bool = F;

event connection_established(c: connection)
    {
    local net_time: time  = network_time();

    print fmt("%s:  New connection established from %s to %s", strftime("%Y/%M/%d %H:%m:%S", net_time), c$id$orig_h, c$id$resp_h);

    if ( connection_seen )
    print fmt("     Time since last connection: %s", net_time - last_connection_time);

    last_connection_time = net_time;
    connection_seen = T;
    }
````
这一次，当我们执行脚本时，我们在输出中看到一个额外的行，显示自上次完全建立的连接以来的时间增量。
````
# bro -r wikipedia.trace data_type_interval.bro
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.118
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.3
     Time since last connection: 132.0 msecs 97.0 usecs
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.3
     Time since last connection: 177.0 usecs
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.3
     Time since last connection: 2.0 msecs 177.0 usecs
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.3
     Time since last connection: 33.0 msecs 898.0 usecs
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.3
     Time since last connection: 35.0 usecs
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.3
     Time since last connection: 2.0 msecs 532.0 usecs
2011/06/18 19:03:08:  New connection established from 141.142.220.118 to 208.80.152.2
     Time since last connection: 7.0 msecs 866.0 usecs
2011/06/18 19:03:09:  New connection established from 141.142.220.235 to 173.192.163.128
     Time since last connection: 817.0 msecs 703.0 usecs
````
#### Pattern
Bro支持使用正则表达式进行快速文本搜索操作，甚至为正则表达式中使用的模式声明本机数据类型。通过在正斜杠字符中包含文本来创建模式常数。 Bro支持与Flex词法分析器语法非常相似的语法。在Bro中最常见的模式使用可能是使用in运算符的嵌入式匹配。嵌入式匹配遵循严格的格式，要求正则表达式或模式常量在in运算符的左侧，要求测试的字符串在右侧。
````
data_type_pattern_01.bro

event bro_init()
{
local test_string = "The quick brown fox jumps over the lazy dog.";
local test_pattern = /quick|lazy/;

if ( test_pattern in test_string )
    {
    local results = split(test_string, test_pattern);
    print results[1];
    print results[2];
    print results[3];
    }
}
````
在上面的示例中，声明了两个局部变量来保存我们的示例句和正则表达式。在这种情况下，如果字符串包含单词quick或单词lazy，我们的正则表达式将返回true。脚本中的if语句使用嵌入式匹配和in运算符来检查字符串中是否存在模式。如果语句解析为true，则调用split以将字符串拆分为单独的片段。 Split使用字符串和模式作为其参数，并返回由计数索引的字符串表。表的每个元素将是与模式匹配的前后的段，但不包括实际匹配。在这种情况下，我们的模式匹配两次，并产生一个包含三个条目的表。脚本中的打印语句将按顺序打印表的内容。
````
# bro data_type_pattern_01.bro
The
 brown fox jumps over the
 dog.
模式也可以用于通过==和！=运算符分别使用等式和不等式运算符来比较字符串。但是，当以这种方式使用时，字符串必须完全匹配才能解析为true。例如，下面的脚本使用两个三元条件语句来说明==运算符与模式的使用。基于模式和字符串之间的比较结果改变输出。

data_type_pattern_02.bro

event bro_init()
{
local test_string = "equality";

local test_pattern = /equal/;
print fmt("%s and %s %s equal", test_string, test_pattern, test_pattern == test_string ? "are" : "are not");

test_pattern = /equality/;
print fmt("%s and %s %s equal", test_string, test_pattern, test_pattern == test_string ? "are" : "are not");
}
````
执行bro脚本：
````
# bro data_type_pattern_02.bro
equality and /^?(equal)$?/ are not equal
equality and /^?(equality)$?/ are equal
````
### Record Data Type
在Bro支持各种数据类型和数据结构的情况下，一个明显的扩展是包括创建由原子类型和其他数据结构组成的自定义数据类型的能力。为了实现这一点，Bro引入了记录类型和类型关键字。与使用typedef和struct关键字在C中定义新数据结构类似，Bro允许您将新数据类型拼凑在一起以适应您的情况。
当与type关键字组合时，record可以生成复合类型。事实上，我们已经在前面的章节中遇到过一个复杂的记录数据类型的例子，连接记录传递给许多事件。另一个，Conn :: Info，它对应于记录到conn.log的字段，由下面的摘录显示。
````
data_type_record.bro

module Conn;

export {
    ## The record type which contains column fields of the connection log.
    type Info: record {
        ts:           time            &log;
        uid:          string          &log;
        id:           conn_id         &log;
        proto:        transport_proto &log;
        service:      string          &log &optional;
        duration:     interval        &log &optional;
        orig_bytes:   count           &log &optional;
        resp_bytes:   count           &log &optional;
        conn_state:   string          &log &optional;
        local_orig:   bool            &log &optional;
        local_resp:   bool            &log &optional;
        missed_bytes: count           &log &default=0;
        history:      string          &log &optional;
        orig_pkts:     count      &log &optional;
        orig_ip_bytes: count      &log &optional;
        resp_pkts:     count      &log &optional;
        resp_ip_bytes: count      &log &optional;
        tunnel_parents: set[string] &log;
    };
}
````
看一下定义的结构，一个新的数据类型集合被定义为一个名为Info的类型。因为这种类型定义在导出块的范围内，所以定义的是事实上的Conn :: Info。
Bro中记录类型的声明的格式化包括要定义的类型的描述性名称和组成记录的单独字段。组成新记录的单个字段在类型或数量上不受限制，只要每个字段的名称是唯一的。
````
data_struct_record_01.bro

type Service: record {
    name: string;
    ports: set[port];
    rfc: count;
};

function print_service(serv: Service)
    {
    print fmt("Service: %s(RFC%d)",serv$name, serv$rfc);

    for ( p in serv$ports )
    print fmt("  port: %s", p);
    }

event bro_init()
    {
    local dns: Service = [$name="dns", $ports=set(53/udp, 53/tcp), $rfc=1035];
    local http: Service = [$name="http", $ports=set(80/tcp, 8080/tcp), $rfc=2616];

    print_service(dns);
    print_service(http);
    }
````
执行上述脚本：
````
# bro data_struct_record_01.bro
Service: dns(RFC1035)
  port: 53/udp
  port: 53/tcp
Service: http(RFC2616)
  port: 8080/tcp
  port: 80/tcp
````
上面的示例显示了一个简单的类型定义，其中包括字符串，一组端口和用于定义服务类型的计数。还包括一个以格式化方式打印记录的每个字段的函数和一个显示处理记录的某些功能的bro_init事件处理程序。 DNS和HTTP服务的定义在传递给print_service函数之前都使用方括号进行内联。 print_service函数使用$ dereference运算符来访问新定义的服务记录类型中的字段。
正如你在Conn :: Info记录的定义中看到的，其他记录甚至有效作为另一个记录中的字段。我们可以扩展上面的示例，以包含另一个包含服务记录的记录。
````
data_struct_record_02.bro

type Service: record {
    name: string;
    ports: set[port];
    rfc: count;
};

type System: record {
    name: string;
    services: set[Service];
 };

function print_service(serv: Service)
    {
    print fmt("  Service: %s(RFC%d)",serv$name, serv$rfc);

    for ( p in serv$ports )
    print fmt("    port: %s", p);
    }

function print_system(sys: System)
    {
    print fmt("System: %s", sys$name);

    for ( s in sys$services )
    print_service(s);
    }

event bro_init()
    {
    local server01: System;
    server01$name = "morlock";
    add server01$services[[ $name="dns", $ports=set(53/udp, 53/tcp), $rfc=1035]];
    add server01$services[[ $name="http", $ports=set(80/tcp, 8080/tcp), $rfc=2616]];
    print_system(server01);


    # local dns: Service = [ $name="dns", $ports=set(53/udp, 53/tcp), $rfc=1035];
    # local http: Service = [ $name="http", $ports=set(80/tcp, 8080/tcp), $rfc=2616];
    # print_service(dns);
    # print_service(http);
    }
````
执行上述脚本：
````
# bro data_struct_record_02.bro
System: morlock
  Service: http(RFC2616)
    port: 8080/tcp
    port: 80/tcp
  Service: dns(RFC1035)
    port: 53/udp
    port: 53/tcp
````
上面的示例包括其中字段用作集合的数据类型的第二记录类型。记录可以重复嵌套在其他记录中，它们的字段可通过$ dereference运算符的重复链来实现。
还常见的一种类型是用于简单地将数据结构别名为更具描述性的名称。下面的示例显示了一个来自Bro自己的类型定义文件的示例。
````
init-bare.bro

type string_array: table[count] of string;
type string_set: set[string];
type addr_set: set[addr];
````
上面的三行将一种类型的数据结构别名为描述性名称。在功能上，操作是相同的，然而，上述每种类型的命名使得它们的功能可立即识别。这是Bro脚本中的另一个地方，其中考虑可以导致代码的更好的可读性，从而在将来更容易维护。

## Custom Logging

通过对Bro中的数据类型和数据结构的正确理解，探索各种可用的框架是一个更有价值的工作。大多数用户可能使用中最多交互的框架是日志框架。以这样一种方式设计，以便抽象创建文件和将组织好的有序的数据附加到其中的大部分过程，记录框架利用一些可能不熟悉的命名。具体来说，日志流，过滤器和写入器只是对管理高速传入日志所需的进程的抽象，同时保持完全可操作性。如果你在一个拥有大量连接的环境中使用Bro，你会发现日志的生成速度非常快，处理大量数据并将其写入磁盘的能力都归功于Logging Framework的设计。
基于Bro的脚本中的决策过程，将数据写入日志流。日志流对应于由组成其字段的 name/value 对集合定义的单个日志。然后，可以使用记录筛选器对数据进行筛选，修改或重定向，这些筛选器默认设置为记录一切。过滤器可用于将日志文件拆分为子集或将该信息复制到另一个输出。数据的最终输出由写入程序定义。 Bro的默认编写器是简单的制表符分隔的ASCII文件，但Bro还支持DataSeries和Elasticsearch输出以及当前正在开发的其他编写器。虽然这些新的术语和想法可能给人的印象是日志框架很难使用，但实际的学习曲线实际上并不是非常陡峭。日志框架中内置的抽象使得绝大多数脚本都很基础。实际上，写入日志文件与定义数据格式一样简单，让Bro知道你希望创建一个新日志，然后调用Log :: write方法来输出日志记录。
日志框架是Bro中的一个区域，你看到它使用的越多，你自己使用的越多，代码的样板部分将越多使用。因此，让我们通过一个简单的例子，简单地记录数字1到10和他们相应的阶乘到默认ASCII日志记录器。最好一次性处理问题，在尝试深入到日志框架之前，使用print和fmt模拟所需的输出。
````
framework_logging_factorial_01.bro

module Factor;

function factorial(n: count): count
    {
    if ( n == 0 )
    return 1;
    else
    return ( n * factorial(n - 1) );
    }

event bro_init()
    {
    local numbers: vector of count = vector(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);

    for ( n in numbers )
    print fmt("%d", factorial(numbers[n]));
    }
````
执行上述脚本：
````
# bro framework_logging_factorial_01.bro
1
2
6
24
120
720
5040
40320
362880
3628800
````
此脚本定义了一个阶乘函数，递归计算作为函数参数传递的无符号整数的阶乘。使用print和fmt，我们可以确保Bro可以正确地执行这些计算，并自己得到答案的想法。
脚本的输出与我们期望的一致，现在是时候集成日志框架。
````
framework_logging_factorial_02.bro

module Factor;

export {
    # Append the value LOG to the Log::ID enumerable.
    redef enum Log::ID += { LOG };

    # Define a new type called Factor::Info.
    type Info: record {
    num:           count &log;
    factorial_num: count &log;
    };
    }

function factorial(n: count): count
    {
    if ( n == 0 )
    return 1;

    else
    return ( n * factorial(n - 1) );
    }

event bro_init()
    {
    # Create the logging stream.
    Log::create_stream(LOG, [$columns=Info, $path="factor"]);
    }

event bro_done()
    {
    local numbers: vector of count = vector(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);    
    for ( n in numbers )
    Log::write( Factor::LOG, [$num=numbers[n],
                              $factorial_num=factorial(numbers[n])]);
    }
````
如上所述，我们必须执行几个步骤，然后才能发出Log :: write方法并生成日志文件。由于我们在命名空间中工作，并向外部实体通知命名空间内部的工作和数据，因此我们使用导出块。首先，我们需要告知Bro，我们将通过向Log :: ID枚举中添加一个值来添加另一个日志流。在这个脚本中，我们将Log值附加到Log :: ID枚举中，但是由于这是一个导出块，附加到Log :: ID的值实际上是Factor :: Log。接下来，我们需要定义构成我们日志数据并指定其格式的名称和值对。此脚本定义了一个名为Info（实际上，Factor :: Info）的新记录数据类型，具有两个字段，两个无符号整数。 Factor :: Log记录类型中的每个字段都包含＆log属性，表示当调用Log :: write时，这些字段应传递到日志框架。如果没有＆log属性的任何名称值对，这些字段将在日志记录期间被忽略，但在变量的生命周期中仍然可用。下一步是使用Log :: create_stream创建日志流，它使用Log :: ID和记录作为其参数。在这个例子中，我们调用Log :: create_stream方法，并传递Factor :: LOG和Factor :: Info记录作为参数。从这里开始，如果我们使用正确的Log :: ID和正确格式化的Factor :: Info记录发出Log :: write命令，将生成一个日志条目。
现在，如果我们运行此脚本，而不是生成到stdout的日志记录信息，则不会创建输出。相反，输出都在factor.log，正确格式化和组织。

````
# bro framework_logging_factorial_02.bro
如下：

#separator \x09
#set_separator    ,
#empty_field      (empty)
#unset_field      -
#path     factor
#open     2016-11-18-19-00-13
#fields   num     factorial_num
#types    count   count
1 1
2 2
3 6
4 24
5 120
6 720
7 5040
8 40320
9 362880
10        3628800
#close    2016-11-18-19-00-13
````
虽然前面的例子是一个简单的例子，它用于演示为了生成日志需要到位的小块脚本代码。例如，通常在bro_init中调用Log :: create_stream，而在实例中，确定何时调用Log :: write可能在事件处理程序中完成，在这种情况下我们使用bro_done。
如果您已经花费了部署Bro的时间，那么您可能有机会查看，搜索或处理由记录框架生成的日志。 Bro的默认安装的日志输出是可以说的，但是，有时候，Logging Framework默认情况下不是理想的方式。这可以包括从每次调用Log :: write时需要记录更多或更少的数据，或者甚至需要基于任意逻辑分割日志文件。在后一种情况下，过滤器与日志框架一起使用。筛选器向Bro的脚本库授予一定级别的自定义，允许脚本作者在日志中包含或排除字段，甚至更改放置日志的文件的路径。每个流创建时，都会提供一个默认过滤器，不出所料，默认为。当使用默认过滤器时，每个具有＆log属性的键值对都将写入单个文件。对于我们一直使用的例子，让我们扩展它，以便写一个因子为5的因子到备用文件，同时将剩余的日志写入factor.log。
````
framework_logging_factorial_03.bro

event bro_init()
    {
    Log::create_stream(LOG, [$columns=Info, $path="factor"]);

    local filter: Log::Filter = [$name="split-mod5s", $path_func=mod5];
    Log::add_filter(Factor::LOG, filter);
    Log::remove_filter(Factor::LOG, "default");
    }
````
要动态更改流写入其日志的文件，过滤器可以指定一个函数，该函数返回一个字符串以用作当前调用Log :: write的文件名。此函数的定义必须以一个称为id的Log :: ID作为其参数，一个名为path的字符串，以及称为rec的日志的相应记录类型。您可以看到本示例中使用的mod5的定义符合该要求。如果阶乘可以被5整除，函数简单地返回factor-mod5，否则返回因子non5。在额外的bro_init事件处理程序中，我们定义一个局部范围的Log :: Filter，并为它分配一个定义名称和path_func字段的记录。然后我们调用Log :: add_filter将过滤器添加到Factor :: LOG Log :: ID并调用Log :: remove_filter来删除Factor :: LOG的默认过滤器。如果我们没有删除默认过滤器，我们最终会得到三个日志文件：factor-mod5.log，所有的因子都是因子5，factor-non5.log的因子不是5的因子，和factor.log，其中包括所有阶乘。
````
# bro framework_logging_factorial_03.bro
如下：

#separator \x09
#set_separator    ,
#empty_field      (empty)
#unset_field      -
#path     factor-mod5
#open     2016-11-18-19-00-14
#fields   num     factorial_num
#types    count   count
5 120
6 720
7 5040
8 40320
9 362880
10        3628800
#close    2016-11-18-19-00-14
````
Bro生成易于定制和可扩展的日志，这些日志保持容易解析的能力是Bro获得了大量重视的重要原因。事实上，有时很难想到Bro不会记录的事情，因此分析师和系统架构师通常会优先考虑日志框架，以便能够根据发送的数据执行自定义操作到记录框。为此，Bro中的每个默认日志流都生成一个自定义事件，任何希望对发送到流的数据执行操作的人都可以处理该事件。按照惯例，这些事件通常采用log_x格式，其中x是日志记录流的名称;因此由HTTP解析器发送到日志记录框架的每个日志引发的事件将是log_http。事实上，我们已经看到一个脚本处理log_http事件，当我们中断了如何检测MHR.bro脚本工作。在该示例中，当每个日志条目发送到日志记录框架时，在log_http事件中进行后处理。代替使用外部脚本来解析http.log文件并对该条目进行后处理，后处理可以在Bro中实时完成。
告诉Bro在自己的Logging流中引发一个事件就像导出该事件名一样简单，然后在调用Log :: create_stream时添加该事件。回到我们记录整数阶乘的简单例子，我们向导出块添加log_factor并定义要传递给它的值，在这种情况下是Factor :: Info记录。然后，我们在调用Log :: create_stream时将log_factor函数列为$ ev字段
````
framework_logging_factorial_04.bro

module Factor;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
    num:           count &log;
    factorial_num: count &log;
    };

    global log_factor: event(rec: Info);
    }

function factorial(n: count): count
    {
    if ( n == 0 )
    return 1;

    else
    return (n * factorial(n - 1));
    }

event bro_init()
    {
    Log::create_stream(LOG, [$columns=Info, $ev=log_factor, $path="factor"]);
    }

event bro_done()
    {
    local numbers: vector of count = vector(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);    
    for ( n in numbers )
    Log::write( Factor::LOG, [$num=numbers[n],
                              $factorial_num=factorial(numbers[n])]);
    }

function mod5(id: Log::ID, path: string, rec: Factor::Info) : string    
    {
    if ( rec$factorial_num % 5 == 0 )
    return "factor-mod5";

    else
    return "factor-non5";
    }

event bro_init()
    {
    local filter: Log::Filter = [$name="split-mod5s", $path_func=mod5];
    Log::add_filter(Factor::LOG, filter);
    Log::remove_filter(Factor::LOG, "default");
    }
````
## Raising Notices
尽管Bro的日志框架提供了一种简单和系统的生成日志的方法，但仍然需要指示何时检测到特定行为，以及允许该检测得到某人注意的方法。为此，“通知框架”已到位，允许脚本作者通过编码方式提出通知，以及运营商可以选择接收通知的系统。 Bro坚持这样的理念，即由个体操作者指示他们感兴趣的行为，并且这样的Bro具有大量的策略脚本，其检测可能感兴趣的行为，但是它不假设为猜测行为是“可行动的”。实际上，Bro致力于分离检测行为和报告责任。使用通知框架，为检测到的任何行为提出通知是很容易的。
要在Bro提出通知，您只需要向Bro表示您通过导出提供一个特定的Notice :: Type，然后致电NOTICE为其提供适当的Notice :: Info记录。通常，对NOTICE的调用只包括Notice :: Type和一个简明的消息。然而，当提醒通知时，有显着更多的选项，如在Notice :: Info的定义中看到的。 Notice :: Info中唯一的属性为必填字段的字段是note字段。然而，良好的方式总是重要的，并且包括$ msg中的简明消息，并且在必要时，$ conn中的连接记录的内容连同Notice ::类型倾向于包括要考虑的通知所需的最少信息有用。如果提供了$ conn变量，Notice Framework将自动填充$ id和$ src字段。通常包括的其他字段，$ identifier和$ suppress_for是围绕“通知框架”的自动抑制功能构建的，我们将在稍后介绍。
其中一个默认策略脚本在启动式检测到SSH登录时发出通知，并且原始主机名将引起怀疑。有效地，脚本尝试定义一个主机列表，您不想从中查看源自SSH流量的DNS流量，例如DNS服务器，邮件服务器等。为了实现这一点，脚本遵循通过检测行为分离检测和报告并提出通知。该通知是否被执行取决于本地通知政策，但脚本尝试提供尽可能多的信息，同时保持简洁。
````
interesting-hostnames.bro

##! This script will generate a notice if an apparent SSH login originates 
##! or heads to a host with a reverse hostname that looks suspicious.  By 
##! default, the regular expression to match "interesting" hostnames includes 
##! names that are typically used for infrastructure hosts like nameservers, 
##! mail servers, web servers and ftp servers.

@load base/frameworks/notice

module SSH;

export {
    redef enum Notice::Type += {
        ## Generated if a login originates or responds with a host where
        ## the reverse hostname lookup resolves to a name matched by the
        ## :bro:id:`SSH::interesting_hostnames` regular expression.
        Interesting_Hostname_Login,
    };

    ## Strange/bad host names to see successful SSH logins from or to.
    const interesting_hostnames =
            /^d?ns[0-9]*\./ |
            /^smtp[0-9]*\./ |
            /^mail[0-9]*\./ |
            /^pop[0-9]*\./  |
            /^imap[0-9]*\./ |
            /^www[0-9]*\./  |
            /^ftp[0-9]*\./  &redef;
}

function check_ssh_hostname(id: conn_id, uid: string, host: addr)
    {
    when ( local hostname = lookup_addr(host) )
        {
        if ( interesting_hostnames in hostname )
            {
            NOTICE([$note=Interesting_Hostname_Login,
                    $msg=fmt("Possible SSH login involving a %s %s with an interesting hostname.",
                             Site::is_local_addr(host) ? "local" : "remote",
                             host == id$orig_h ? "client" : "server"),
                    $sub=hostname, $id=id, $uid=uid]);
            }
        }
    }

event ssh_auth_successful(c: connection, auth_method_none: bool)
    {
    for ( host in set(c$id$orig_h, c$id$resp_h) )
        {
        check_ssh_hostname(c$id, c$uid, host);
        }
    }
````
虽然大部分脚本与实际检测有关，但“通知框架”特有的部分本身实际上是相当有趣的。脚本的导出块将值SSH :: Interesting_Hostname_Login添加到可枚举常量Notice :: Type中，以向Bro核指示正在定义新类型的通知。脚本然后调用NOTICE并定义Notice :: Info记录的$ note，$ msg，$ sub，id和$ uid字段。 （更常见的是，将设置$ conn，但是这个脚本为了性能原因避免使用在when语句内的连接记录）。有两个三元if语句修改$ msg文本取决于主机是否是本地地址以及它是客户端还是服务器。这种使用fmt和三元运算符是一种简单的方式，可以为生成的通知提供可读性，而无需分支（如果每个语句都提出特定通知）。
通知的选择加入系统通过写Notice ::策略钩子来管理。 Notice :: policy钩子接受一个Notice :: Info记录作为其参数，它将保存你的脚本在调用NOTICE中提供的相同信息。通过访问Notice :: Info记录获取特定通知，您可以在挂钩的正文中包含诸如in语句的逻辑，以更改系统上处理通知的策略。在Bro中，钩子类似于函数和事件处理器的混合：类似函数，对它们的调用是同步的（即运行到完成和返回）;但像事件，他们可以有多个机构，都将执行。为了定义通知策略，您定义一个钩子，Bro将负责传递Notice :: Info记录。最简单的Notice :: policy钩子只是检查在通知挂钩中的Notice :: Info记录中的$ note的值，并根据答案执行一个动作。下面的钩子为在策略/ protocols / ssh / interesting-hostnames.bro脚本中引发的SSH :: Interesting_Hostname_Login通知添加Notice :: ACTION_EMAIL操作。
````
framework_notice_hook_01.bro

@load policy/protocols/ssh/interesting-hostnames.bro

hook Notice::policy(n: Notice::Info)
  {
  if ( n$note == SSH::Interesting_Hostname_Login )
      add n$actions[Notice::ACTION_EMAIL];
  }
````
在上面的例子中，我们添加了Notice :: ACTION_EMAIL到n $ actions集。在Notice框架脚本中定义的此集合只能包含Notice :: Action类型的条目，它本身是可枚举的，它定义下表中显示的值及其相应的含义。 Notice :: ACTION_LOG操作将通知写入Notice :: LOG记录流，在默认配置中，它将每个通知写入notice.log文件，并且不进行进一步操作。 Notice :: ACTION_EMAIL操作将发送电子邮件到Notice :: mail_dest变量中定义的地址或地址，通知的详细信息将作为电子邮件的正文。最后一个操作，Notice :: ACTION_ALARM发送通知到Notice :: ALARM_LOG日志流，然后每小时旋转它的内容，并且其内容以可读ASCII以电子邮件发送到Notice :: mail_dest中的地址。
````
ACTION_NONE	Take no action
ACTION_LOG	Send the notice to the Notice::LOG logging stream.
ACTION_EMAIL	Send an email with the notice in the body.
ACTION_ALARM	Send the notice to the Notice::Alarm_LOG stream.
````
虽然Notice :: ACTION_EMAIL操作等操作具有快速警报和响应的吸引力，但是使用它的一个警告是确保配置了此操作的通知也具有抑制。抑制是一种手段，通过它们，如果脚本的作者已经设置了标识符，则在最初引发之后可以忽略通知。标识符是从连接相对于Bro所观察到的行为收集的唯一的信息字符串。
````
expiring-certs.bro

NOTICE([$note=Certificate_Expires_Soon,
            $msg=fmt("Certificate %s is going to expire at %T", cert$subject, cert$not_valid_after),
            $conn=c, $suppress_for=1day,
            $identifier=cat(c$id$resp_h, c$id$resp_p, hash),
            $fuid=fuid]);
````

在策略/ protocols / ssl / expiring-certs.bro脚本中，该脚本标识何时SSL证书设置为过期，并在超过预定义阈值时引发通知，对上述NOTICE的调用还通过连接响应者IP设置$标识符条目，端口和证书的散列。响应者IP，端口和证书哈希的选择完全适合于适当的标识符，因为它创建了可以与其匹配的抑制的唯一标识符。如果我们取出用于标识符的任何实体，例如证书哈希，我们可能将我们的抑制设置得过于宽泛，导致分析人员错过了应该提出的通知。根据标识符的可用数据，设置$ suppress_for变量也很有用。 expiring-certs.bro脚本将$ suppress_for设置为1天，告知通知框架在第一个通知提出后24小时禁止通知。一旦该时间限制过去，可以提出另一个通知，其将再次设置1天抑制时间。抑制在特定时间量具有超越简单地不填写分析师的电子邮件收件箱的好处;及时和简明地保持通知警报有助于避免分析人员可能看到通知并且由于过度暴露而忽略它的情况。
$ suppress_for变量也可以在Notice :: policy钩子中改变，允许部署更好地适合运行它的环境。使用expiring-certs.bro的示例，我们可以为SSL :: Certificate_Expires_Soon写一个Notice :: policy钩子，以将$ suppress_for变量配置为更短的时间。
````
framework_notice_hook_suppression_01.bro

@load policy/protocols/ssl/expiring-certs.bro

hook Notice::policy(n: Notice::Info) 
   {
   if ( n$note == SSL::Certificate_Expires_Soon )
       n$suppress_for = 12hrs;
   }
````
虽然Notice :: policy钩子允许您为部署构建自定义的基于谓词的策略，但是有一定次数，您不需要钩子允许的完全表达。简而言之，将有通知政策考虑，其中可以基于Notice :: Type单独做出广泛决定。为了促进这些类型的决策，“通知框架”支持“通知政策”快捷方式。这些快捷方式通过一组数据结构的方法来实现，这些数据结构将特定的，预定义的细节和动作映射到通知的有效名称。主要实现为Notice :: Type的枚举集或表，Notice Policy快捷方式可以作为一个简单的指令放置在local.bro文件中作为简明易读的配置。由于这些变量都是常量，因此需要提到这些变量都是在Bro完全启动并运行并且不是动态设置之前在解析时设置的。
````
Name	Description	Data Type
Notice::ignored_types	Ignore the Notice::Type entirely	set[Notice::Type]
Notice::emailed_types	Set Notice::ACTION_EMAIL to this Notice::Type	set[Notice::Type]
Notice::alarmed_types	Set Notice::ACTION_ALARM to this Notice::Type	set[Notice::Type]
Notice::not_suppressed_types	Remove suppression from this Notice::Type	set[Notice::Type]
Notice::type_suppression_intervals	Alter the $suppress_for value for this Notice::Type	table[Notice::Type] of interval
````
上表详细说明了五个Notice Policy快捷方式，它们的含义和用于实现它们的数据类型。除了Notice :: type_suppression_intervals之外，设置数据类型用于保存应该应用快捷方式的通知的Notice :: Type。前三个快捷键是相当自解释的，对集合中的Notice :: Type元素应用动作，而后两个快捷键更改应用于通知的抑制的细节。快捷方式Notice :: not_suppressed_types可用于从通知中删除配置的抑制，Notice :: type_suppression_intervals可用于更改由$ suppress_for在调用NOTICE中定义的抑制间隔。
````
framework_notice_shortcuts_01.bro

@load policy/protocols/ssh/interesting-hostnames.bro
@load base/protocols/ssh/

redef Notice::emailed_types += {
    SSH::Interesting_Hostname_Login
};
````
上面的Notice Policy快捷方式将Notice :: Type of SSH :: Interesting_Hostname_Login添加到Notice :: emailed_types集，而下面的快捷方式更改了那些通知被抑制的时间长度。
````
framework_notice_shortcuts_02.bro

@load policy/protocols/ssh/interesting-hostnames.bro
@load base/protocols/ssh/

redef Notice::type_suppression_intervals += {
    [SSH::Interesting_Hostname_Login] = 1day,
};
````
